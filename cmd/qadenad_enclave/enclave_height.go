package main

// Height bookkeeping for the enclave's store.
//
// The enclave commits its state through a rootmulti/IAVL CommitMultiStore, whose version counter
// is DENSE: Commit() is always previousVersion+1 (vendor/cosmossdk.io/store/rootmulti/store.go,
// Commit), so versions cannot skip and can never be made equal to chain heights -- an enclave
// that missed 12,000 blocks could not jump its version forward to match.  Worse, not every commit
// belongs to a height at all: SyncEnclave commits out-of-band while seeding a new node.
//
// So heights are MAPPED to versions rather than equated with them, in three pieces:
//
//   preparedHeight   the last chain height whose writes this store has committed.  Stamped INSIDE
//                    the committed IAVL version (EnclavePreparedHeightKeyPrefix), so it travels
//                    with the tree: roll the tree back and the stamp rolls back with it, making
//                    every version self-describing.
//
//   confirmedHeight  the last height the CHAIN has told us it durably committed.  A raw goleveldb
//                    key OUTSIDE the tree, deliberately: it must survive a tree rollback, because
//                    it is the record of what the rest of the network has that we cannot un-know.
//
//   qmeta/hv/<H>     height -> IAVL version, one entry per EndBlock commit.  This is what makes
//                    RollbackToHeight O(1) instead of a search, and its ABSENCE for a version is
//                    meaningful: a version with no entry is an out-of-band commit (SyncEnclave)
//                    that no rollback should ever target.
//
// Everything under qmeta/ is deliberately UNSEALED plaintext: heights are not secrets, and an
// operator recovering a broken node must be able to read them with `leveldb dump` on a machine
// that does not have this enclave's product key.
//
// The qmeta/ namespace cannot collide with rootmulti's own raw keys, which live under
// "s/" ("s/latest", "s/<version>", "s/k:<name>/...").

import (
	"context"
	"fmt"
	"strconv"

	"strings"

	"cosmossdk.io/store/prefix"
	pruningtypes "cosmossdk.io/store/pruning/types"
	storetypes "cosmossdk.io/store/types"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"
	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

const (
	// current on-disk layout of the enclave's stores.  Greenfield: there is no schema-0 reader --
	// a store stamped with a LOWER version than this refuses to run (chains are rebuilt from
	// genesis rather than migrated), and a HIGHER version means the operator is running an old
	// binary against a newer node's data, which must also refuse rather than mangle it.
	enclaveSchemaVersion uint32 = 1

	qmetaSchemaKey          = "qmeta/schema"
	qmetaConfirmedHeightKey = "qmeta/confirmed_height"
	qmetaHVPrefix           = "qmeta/hv/"

	// the single row key under EnclavePreparedHeightKeyPrefix
	preparedHeightRowKey = "height/"
)

// qmetaHVKey zero-pads the height to 20 digits so lexicographic order equals numeric order --
// which is what lets earliestIndexedHeight read the first key of a forward iterator and
// deleteHeightIndexAbove use a simple range.
// Version retention, matching the chain's pruning "default" window so the enclave can follow any
// rollback the chain itself can perform.  The hv index is pruned one interval TIGHTER than the
// versions (see EndBlock), so an indexed height is always backed by a live version -- a stale
// entry would send RollbackToHeight into a deep IAVL failure instead of a refusal by name.
//
// VARIABLES, not constants, solely so tests can shrink the window: at 362,880 a test chain would
// have to run for weeks before pruning triggered even once, which is precisely how retention
// bugs reach production unexercised.  Nothing at runtime writes to these.
var (
	enclaveRetainVersions uint64 = 362880
	enclavePruneInterval  uint64 = 100
)

func qmetaHVKey(height int64) []byte {
	return []byte(fmt.Sprintf("%s%020d", qmetaHVPrefix, height))
}

// ---- preparedHeight: versioned, inside the tree ----

func (s *qadenaServer) getPreparedHeight() int64 {
	store := prefix.NewStore(s.ServerCtx.KVStore(s.StoreKey), types.KeyPrefix(EnclavePreparedHeightKeyPrefix))
	b := store.Get([]byte(preparedHeightRowKey))
	if b == nil {
		return 0
	}
	h, err := strconv.ParseInt(string(b), 10, 64)
	if err != nil {
		// this key is only ever written by setPreparedHeight below; a parse failure means the
		// store is corrupt in a way no fallback can paper over
		panic("qadena enclave: corrupt prepared-height record: " + err.Error())
	}
	return h
}

// setPreparedHeight writes through the transaction cache, exactly like every other versioned
// write, so the stamp lands in the same IAVL version as the block's own writes when EndBlock
// promotes and commits the cache.
func (s *qadenaServer) setPreparedHeight(height int64) {
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(EnclavePreparedHeightKeyPrefix))
	store.Set([]byte(preparedHeightRowKey), []byte(strconv.FormatInt(height, 10)))
}

// ---- confirmedHeight: raw, outside the tree ----

func (s *qadenaServer) getConfirmedHeight() int64 {
	b, err := s.MetaDB.Get([]byte(qmetaConfirmedHeightKey))
	if err != nil {
		panic("qadena enclave: cannot read confirmed height: " + err.Error())
	}
	if b == nil {
		return 0
	}
	h, err := strconv.ParseInt(string(b), 10, 64)
	if err != nil {
		panic("qadena enclave: corrupt confirmed-height record: " + err.Error())
	}
	return h
}

func (s *qadenaServer) setConfirmedHeight(height int64) {
	// SetSync: this is the watermark the chain relies on across a crash, so it must not sit in an
	// OS buffer when the process dies
	if err := s.MetaDB.SetSync([]byte(qmetaConfirmedHeightKey), []byte(strconv.FormatInt(height, 10))); err != nil {
		panic("qadena enclave: cannot persist confirmed height: " + err.Error())
	}
}

// ---- height -> version index: raw, outside the tree ----

func (s *qadenaServer) setHeightVersion(height int64, version int64) {
	if err := s.MetaDB.SetSync(qmetaHVKey(height), []byte(strconv.FormatInt(version, 10))); err != nil {
		panic("qadena enclave: cannot persist height->version index: " + err.Error())
	}
}

// getHeightVersion returns (version, found).
func (s *qadenaServer) getHeightVersion(height int64) (int64, bool) {
	b, err := s.MetaDB.Get(qmetaHVKey(height))
	if err != nil {
		panic("qadena enclave: cannot read height->version index: " + err.Error())
	}
	if b == nil {
		return 0, false
	}
	v, err := strconv.ParseInt(string(b), 10, 64)
	if err != nil {
		panic("qadena enclave: corrupt height->version record: " + err.Error())
	}
	return v, true
}

// earliestIndexedHeight is the rollback horizon: the lowest height still present in the index.
// 0 means the index is empty (a store from before height bookkeeping, or a fresh one).
func (s *qadenaServer) earliestIndexedHeight() int64 {
	it, err := s.MetaDB.Iterator([]byte(qmetaHVPrefix), storetypes.PrefixEndBytes([]byte(qmetaHVPrefix)))
	if err != nil {
		panic("qadena enclave: cannot iterate height->version index: " + err.Error())
	}
	defer it.Close()
	if !it.Valid() {
		return 0
	}
	h, err := strconv.ParseInt(string(it.Key()[len(qmetaHVPrefix):]), 10, 64)
	if err != nil {
		panic("qadena enclave: corrupt height->version key: " + err.Error())
	}
	return h
}

// deleteHeightIndexAbove removes every index entry for heights strictly greater than the target.
// Used by rollback: those versions no longer exist in the tree, and a map entry pointing at a
// deleted version would send a later rollback into a deep IAVL failure instead of a refusal.
func (s *qadenaServer) deleteHeightIndexAbove(height int64) {
	it, err := s.MetaDB.Iterator(qmetaHVKey(height+1), storetypes.PrefixEndBytes([]byte(qmetaHVPrefix)))
	if err != nil {
		panic("qadena enclave: cannot iterate height->version index: " + err.Error())
	}
	var doomed [][]byte
	for ; it.Valid(); it.Next() {
		k := make([]byte, len(it.Key()))
		copy(k, it.Key())
		doomed = append(doomed, k)
	}
	it.Close()
	for _, k := range doomed {
		if err := s.MetaDB.DeleteSync(k); err != nil {
			panic("qadena enclave: cannot prune height->version index: " + err.Error())
		}
	}
}

// deleteHeightIndexBelow removes every index entry for heights strictly less than the target.
// Called from EndBlock as versions fall out of the pruning window; the range is almost always a
// single entry.
func (s *qadenaServer) deleteHeightIndexBelow(height int64) {
	it, err := s.MetaDB.Iterator([]byte(qmetaHVPrefix), qmetaHVKey(height))
	if err != nil {
		panic("qadena enclave: cannot iterate height->version index: " + err.Error())
	}
	var doomed [][]byte
	for ; it.Valid(); it.Next() {
		k := make([]byte, len(it.Key()))
		copy(k, it.Key())
		doomed = append(doomed, k)
	}
	it.Close()
	for _, k := range doomed {
		if err := s.MetaDB.DeleteSync(k); err != nil {
			panic("qadena enclave: cannot prune height->version index: " + err.Error())
		}
	}
}

// ---- schema ----

func (s *qadenaServer) getSchemaVersion() uint32 {
	b, err := s.MetaDB.Get([]byte(qmetaSchemaKey))
	if err != nil {
		panic("qadena enclave: cannot read schema version: " + err.Error())
	}
	if b == nil {
		return 0
	}
	v, err := strconv.ParseUint(string(b), 10, 32)
	if err != nil {
		panic("qadena enclave: corrupt schema record: " + err.Error())
	}
	return uint32(v)
}

// initSchema stamps a fresh store and refuses a mismatched one.  Called once at startup, after
// LoadLatestVersion and before the gRPC listener, never in read-only (upgrade) mode.
func (s *qadenaServer) initSchema() error {
	have := s.getSchemaVersion()
	switch {
	case have == enclaveSchemaVersion:
		return nil
	case have == 0:
		// Either a brand-new store or one from before height bookkeeping.  Greenfield policy:
		// pre-bookkeeping stores are not migrated, they are rebuilt -- but a store that is empty
		// EXCEPT for the missing marker is simply new, and stamping it is the normal path.
		if v := s.latestVersion(); v != 0 {
			return fmt.Errorf("enclave store has %d committed versions but no schema marker: it predates height bookkeeping and cannot be migrated -- rebuild this node from genesis (or sync-enclave) instead", v)
		}
		if err := s.MetaDB.SetSync([]byte(qmetaSchemaKey), []byte(strconv.FormatUint(uint64(enclaveSchemaVersion), 10))); err != nil {
			return fmt.Errorf("cannot stamp schema version: %w", err)
		}
		return nil
	case have < enclaveSchemaVersion:
		return fmt.Errorf("enclave store schema %d is older than this binary's %d and there is no migration path -- rebuild this node from genesis", have, enclaveSchemaVersion)
	default:
		return fmt.Errorf("enclave store schema %d is NEWER than this binary's %d -- this binary is too old for this node's data; refusing rather than mangling it", have, enclaveSchemaVersion)
	}
}

func (s *qadenaServer) latestVersion() int64 {
	cms, ok := s.ServerCtx.MultiStore().(storetypes.CommitMultiStore)
	if !ok {
		panic("qadena enclave: multistore is not a CommitMultiStore")
	}
	return cms.LastCommitID().Version
}

// ---- RPC ----

func (s *qadenaServer) GetEnclaveHeight(ctx context.Context, in *types.MsgGetEnclaveHeight) (*types.GetEnclaveHeightReply, error) {
	reply := &types.GetEnclaveHeightReply{
		PreparedHeight:  s.getPreparedHeight(),
		ConfirmedHeight: s.getConfirmedHeight(),
		LatestVersion:   s.latestVersion(),
		EarliestHeight:  s.earliestIndexedHeight(),
		SchemaVersion:   s.getSchemaVersion(),
	}
	c.LoggerDebug(logger, "GetEnclaveHeight "+c.PrettyPrint(reply))
	return reply, nil
}

// RollbackToHeight rewinds the enclave's versioned store to the state it committed for the given
// chain height.  The secrets DB (enclave_secrets.go) is untouched by construction -- it is not
// part of the tree this operates on -- which is exactly the asymmetry the split exists for.
//
// Refusals are gRPC ERRORS so no caller can mistake "did not roll back" for success; the two
// benign outcomes (already at the height, dry run) return a reply with RolledBack=false and a
// Reason instead.
//
// CONCURRENCY: this must not run while a block is executing.  Both callers guarantee that -- the
// CLI path runs with qadenad down (so nothing drives the enclave), and the startup
// reconciliation path runs from BeginBlock before any transaction of the first block executes.
func (s *qadenaServer) RollbackToHeight(ctx context.Context, in *types.MsgRollbackToHeight) (*types.RollbackToHeightReply, error) {
	prepared := s.getPreparedHeight()
	fromVersion := s.latestVersion()

	reply := &types.RollbackToHeightReply{
		FromHeight:  prepared,
		ToHeight:    in.Height,
		FromVersion: fromVersion,
	}

	if in.Height <= 0 {
		return nil, fmt.Errorf("invalid rollback target height %d", in.Height)
	}

	if in.Height > prepared {
		// The enclave is BEHIND the requested height.  There is nothing here to roll back, and
		// pretending otherwise would hide the real situation: it is the CHAIN that must come back
		// to the enclave (or further), not the enclave forward.
		return nil, fmt.Errorf("enclave is at height %d, behind the requested %d: nothing to roll back -- roll the chain back to %d or below instead", prepared, in.Height, prepared)
	}

	if in.Height == prepared {
		// idempotent no-op: the chain-side rollback command may be run repeatedly
		reply.ToVersion = fromVersion
		reply.Reason = fmt.Sprintf("already at height %d", prepared)
		c.LoggerInfo(logger, "RollbackToHeight: "+reply.Reason)
		return reply, nil
	}

	v, found := s.getHeightVersion(in.Height)
	if !found {
		// Never guess.  A missing entry means either the height is below the rollback horizon or
		// it was never an EndBlock commit on this store; both are refusals by name.
		return nil, fmt.Errorf("no version is indexed for height %d (rollback horizon is height %d): cannot roll back to a height this store never committed", in.Height, s.earliestIndexedHeight())
	}

	reply.ToVersion = v

	if in.DryRun {
		reply.Reason = fmt.Sprintf("dry run: would roll back from height %d (version %d) to height %d (version %d)", prepared, fromVersion, in.Height, v)
		c.LoggerInfo(logger, "RollbackToHeight: "+reply.Reason)
		return reply, nil
	}

	cms, ok := s.ServerCtx.MultiStore().(storetypes.CommitMultiStore)
	if !ok {
		return nil, fmt.Errorf("enclave multistore is not a CommitMultiStore; cannot roll back")
	}

	c.LoggerInfo(logger, fmt.Sprintf("RollbackToHeight: rolling back from height %d (version %d) to height %d (version %d)", prepared, fromVersion, in.Height, v))

	// LoadVersionForOverwriting deletes every version above v and rebuilds the fast-node index,
	// so a deep rollback takes real time -- callers use a generous timeout, not c.DebugTimeout
	if err := cms.RollbackToVersion(v); err != nil {
		return nil, fmt.Errorf("rollback to version %d (height %d) failed: %w", v, in.Height, err)
	}

	// prune index entries whose versions no longer exist -- a stale entry would send a later
	// rollback into a deep IAVL failure instead of a refusal by name
	s.deleteHeightIndexAbove(in.Height)

	// the chain cannot have durably committed beyond where we now are; clamp the watermark
	if s.getConfirmedHeight() > in.Height {
		s.setConfirmedHeight(in.Height)
	}

	// the old transaction cache wraps a tree that no longer exists (ServerCtx itself is fine:
	// it holds the rootmulti pointer, which RollbackToVersion mutates in place)
	s.CacheCtx, s.CacheCtxWrite = s.ServerCtx.CacheContext()

	// The delivery queues live in the versioned outbox (enclave_outbox.go), so the rollback we
	// just performed has already restored them to exactly what the unwound blocks must
	// re-deliver on re-execution.  Only the intra-transaction pending list is RAM, and any
	// transaction it belonged to no longer exists.
	s.pendingSuspiciousTransactions = nil

	reply.RolledBack = true
	c.LoggerInfo(logger, fmt.Sprintf("RollbackToHeight: done -- now at height %d, version %d", s.getPreparedHeight(), s.latestVersion()))
	return reply, nil
}

// ConfirmHeight is the second phase of the two-phase commit: the chain calls it AFTER
// BaseApp.Commit has made the block durable (the app.Commit override in app/app.go).  All it
// does is advance the confirmed watermark -- the state itself became durable at the EndBlock
// prepare.  The prepared==confirmed pair is what startup reconciliation later reads to decide
// whether a crash landed in the window between the enclave's commit and the chain's.
func (s *qadenaServer) ConfirmHeight(ctx context.Context, in *types.MsgConfirmHeight) (*types.ConfirmHeightReply, error) {
	prepared := s.getPreparedHeight()
	if in.Height != prepared {
		// Confirming a height we did not prepare would assert durability of state this store
		// does not hold.  A mismatch here means chain and enclave have already diverged; the
		// chain halts on this error and reconciliation sorts it out at restart.
		return nil, fmt.Errorf("cannot confirm height %d: the enclave's prepared height is %d", in.Height, prepared)
	}
	confirmed := s.getConfirmedHeight()
	if in.Height < confirmed {
		return nil, fmt.Errorf("cannot confirm height %d: already confirmed through %d", in.Height, confirmed)
	}
	s.setConfirmedHeight(in.Height)
	return &types.ConfirmHeightReply{ConfirmedHeight: in.Height}, nil
}

// enclavePruningOptions mirrors the chain's server.GetPruningOptionsFromFlags so both sides read
// the same strategy names out of the same config/app.toml and land on the same numbers.  Kept as
// a small local function rather than importing the SDK's, which takes an AppOptions the enclave
// has no reason to construct.
func enclavePruningOptions(strategy string, keepRecent, interval uint64) (pruningtypes.PruningOptions, error) {
	switch strings.ToLower(strategy) {
	case pruningtypes.PruningOptionDefault, pruningtypes.PruningOptionNothing, pruningtypes.PruningOptionEverything:
		return pruningtypes.NewPruningOptionsFromString(strings.ToLower(strategy)), nil
	case pruningtypes.PruningOptionCustom:
		opts := pruningtypes.NewCustomPruningOptions(keepRecent, interval)
		if err := opts.Validate(); err != nil {
			return opts, fmt.Errorf("invalid custom pruning options: %w", err)
		}
		return opts, nil
	default:
		return pruningtypes.PruningOptions{}, fmt.Errorf("unknown pruning strategy %q (expected default, nothing, everything or custom)", strategy)
	}
}
