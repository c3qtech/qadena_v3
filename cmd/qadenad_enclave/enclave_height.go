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

	"cosmossdk.io/store/prefix"
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
