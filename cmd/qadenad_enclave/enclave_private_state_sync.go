package main

// Enclave-to-enclave transfer of the PRIVATE tables at a single height.
//
// A node that joins by chain state-sync restores chain state at H without executing blocks 1..H,
// so it never produces the enclave-private tables that only block execution writes.  The nine
// chain-mirrored prefixes are re-pushed from chain state; these are not derivable from anything
// the chain holds.  Without them the node runs with an empty AML window and forks (see the case-F
// halt in x/qadena/keeper/enclave_grpc_client.go).
//
// WHY A SINGLE HEIGHT AND NOT A HISTORY.  No consensus path reads a past version of any private
// table -- every read goes through s.CacheCtx, and the only versioned readers are the debug export
// and operator rollback.  So the transfer is one flat snapshot at H, written as a single version.
// The receiver's store therefore begins at H and cannot roll back below its join height, which is
// exactly the chain's own semantics after a state-sync.
//
// WHY IT CANNOT BE A BYTE COPY.  MustSeal derives from the product key, which per ego is bound to
// the enclave AND THE CPU, and MustSealStable derives from SealedTableSharedSecret, minted per node
// at preInitEnclave and never transmitted.  A sealed row is meaningless on another machine in both
// directions, so the only possible shape is unseal-at-source / re-seal-at-destination -- which is
// why the payload is plaintext in flight and must be encrypted to the receiver's enclave key.
//
// Re-sealing costs nothing to implement because the import writes through the ordinary setters,
// which already seal with THIS node's secrets.

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"cosmossdk.io/store/prefix"
	storetypes "cosmossdk.io/store/types"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"
	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

const (
	// Page budget, measured on the PLAINTEXT page before compression.
	//
	// Every hop runs on grpc-go defaults -- 4 MiB receive, no overrides anywhere in this repo -- and
	// the tightest is the SERVING node's qadenad receiving its own enclave's reply over the unix
	// socket.  The reply then travels as CometBFT RPC JSON, where bytes are base64 and inflate 4/3.
	//
	// Budgeting on plaintext is safe rather than approximate: gzip only ever shrinks (its worst
	// case is a fraction of a percent of overhead) and encryption adds a small constant, so a 1 MiB
	// plaintext page can never produce a ciphertext anywhere near 4 MiB.  Measuring the ciphertext
	// instead would mean building, compressing, encrypting and then possibly discarding a page.
	privateStatePageTargetBytes = 1 << 20 // 1 MiB

	// Absolute ceiling on the encrypted page actually put on the wire.  A backstop for the
	// reasoning above rather than the normal control: if this ever trips, something is wrong with
	// the budget, and failing loudly beats a truncated transfer.
	privateStatePageHardLimitBytes = 3 << 20 // 3 MiB

	// A SINGLE row above this cannot be transferred at all.  One AML row is one sender's whole
	// window, so a hot wallet's row is the realistic worst case.  Erroring by name is deliberate:
	// skipping the row would hand the joiner a window that is quietly missing a sender, which is
	// precisely the silent divergence this file exists to prevent.
	privateStateMaxRowBytes = 3 << 20 // 3 MiB
)

// privateStateTableKind selects how a row is decoded and re-written; the tables differ in value
// shape, not in key shape (all five use MustSealStable(EnclaveKeyKey(...))).
type privateStateTableKind int

const (
	kindSealedString privateStateTableKind = iota
	kindIdentityHistory
	kindScanHistory
)

type privateStateTable struct {
	prefix string
	kind   privateStateTableKind
}

// privateStateTables is ORDER-SENSITIVE: the cursor's table index refers to positions in this
// slice, so reordering it breaks resumption mid-transfer between versions.  Append only.
//
// What is deliberately absent matters as much as what is here:
//
//	EnclaveCredentialPCXY          rebuilt locally -- SetCredential writes it from chain state with
//	                               no key material and no network, so shipping it is pure waste.
//	SS shares / privK cache        NEVER transferred.  The threshold model says a node holds only
//	                               its own shares; getSSPrivK reconstructs the rest from owners at
//	                               runtime.  Sending them would defeat the entire scheme.
//	Enclave/Outbox                 node-local delivery queue.  By the delivery-order invariant, the
//	                               peer's rows for heights <= H were already drained into chain
//	                               state, which the snapshot contains -- importing them would
//	                               re-deliver at H+1 and fork.  The import refuses if ours is
//	                               non-empty.
//	EnclavePreparedHeight          node-local; left at 0 so the first EndBlock adopts H+1.
var privateStateTables = []privateStateTable{
	{EnclaveScanTransferHistoryKeyPrefix, kindScanHistory},
	{EnclaveCredentialHashKeyPrefix, kindSealedString},
	{EnclaveCredentialHashesByCredentialIDKeyPrefix, kindIdentityHistory},
	{EnclaveProtectSubWalletIDByOriginalWalletIDKeyPrefix, kindSealedString},
	{EnclaveRecoverOriginalWalletIDByNewWalletIDKeyPrefix, kindSealedString},
}

// qmetaPrivateSyncHeightKey records that a COMPLETED import landed, and at what height.  Raw
// MetaDB, outside the tree, for the same reason confirmedHeight lives there: it must survive a
// rollback of the tree, because it is a record of provenance rather than of state.
const qmetaPrivateSyncHeightKey = "qmeta/private_sync_height"

// qmetaPrivateSyncProgressKey records an IN-PROGRESS import so it can resume.
//
// It exists because of enclave memory.  The obvious shape -- apply every page into the transaction
// cache and commit once at the end -- is atomic but holds the ENTIRE private state in RAM before
// anything is durable.  Inside an SGX enclave, where usable EPC is tens to a couple of hundred
// megabytes and spilling past it means punishing paging, that is how an import of a busy chain
// becomes an OOM.
//
// So pages are committed as they arrive and progress is recorded here, which bounds live memory to
// roughly one page.  Atomicity is preserved where it actually matters, because the AUTHORITY on
// whether this enclave has usable private state is the COMPLETED marker above, never the presence
// of rows: a crash mid-import leaves rows plus a progress marker and no completed marker, which is
// distinguishable from both a finished import and a fresh enclave, and simply resumes.
const qmetaPrivateSyncProgressKey = "qmeta/private_sync_progress"

type privateStateProgress struct {
	Height int64  `json:"h"`
	Cursor []byte `json:"c"`
	Rows   int    `json:"r"`
	Pages  int    `json:"p"`
}

// privateStateCursor is an opaque resume point.
//
// The key is PLAINTEXT, which is forced rather than chosen: rows are stored under stable-sealed
// keys, and stable sealing is per-node, so a sealed key from the server would be meaningless to
// the client and vice versa.  The server re-seals this with its OWN secret to seek, which works
// because MustSealStable is deterministic (the whole store depends on that -- it is how any row is
// ever looked up again).
type privateStateCursor struct {
	Table int    `json:"t"`
	Key   string `json:"k"`
}

func encodeCursor(cur privateStateCursor) []byte {
	b, err := json.Marshal(cur)
	if err != nil {
		panic("qadena enclave: cannot encode private-state cursor: " + err.Error())
	}
	return b
}

func decodeCursor(b []byte) (privateStateCursor, error) {
	var cur privateStateCursor
	if len(b) == 0 {
		return privateStateCursor{}, nil
	}
	if err := json.Unmarshal(b, &cur); err != nil {
		return cur, fmt.Errorf("malformed private-state cursor: %w", err)
	}
	if cur.Table < 0 || cur.Table > len(privateStateTables) {
		return cur, fmt.Errorf("private-state cursor names table %d, but this enclave has %d", cur.Table, len(privateStateTables))
	}
	return cur, nil
}

// ---- compression, applied BEFORE encryption ----
//
// That order is the only one that helps: ciphertext is high-entropy and does not compress.  The
// window compresses well because wallet IDs, denoms and destination IDs repeat across every entry.
//
// The tradeoff, recorded rather than hidden: compressing attacker-influenceable content and then
// encrypting leaks a little through ciphertext LENGTH -- someone who can make transfers and observe
// page sizes learns something about how compressible the rest of the window is.  Acceptable here
// because this is a bulk transfer that happens once at join rather than a repeatable oracle, but it
// is the reason page size must not become a per-request tunable beyond the clamp below.

func gzipBytes(plain []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(plain); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func gunzipBytes(zipped []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(zipped))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	// io.ReadAll is bounded in practice by the caller having already accepted the ciphertext under
	// privateStatePageHardLimitBytes; a decompression bomb from an ATTESTED peer running the same
	// measurement is not in the threat model.
	return io.ReadAll(r)
}

// ---- server: serve a page at a height ----

func (s *qadenaServer) QueryEnclavePrivateStateAvailability(goCtx context.Context, in *types.QueryEnclavePrivateStateAvailabilityRequest) (*types.QueryEnclavePrivateStateAvailabilityResponse, error) {
	return &types.QueryEnclavePrivateStateAvailabilityResponse{
		EarliestHeight: s.earliestIndexedHeight(),
		PreparedHeight: s.getPreparedHeight(),
		SchemaVersion:  s.getSchemaVersion(),
	}, nil
}

func (s *qadenaServer) QueryEnclavePrivateState(goCtx context.Context, in *types.QueryEnclavePrivateStateRequest) (*types.QueryEnclavePrivateStateResponse, error) {
	c.LoggerDebug(logger, fmt.Sprintf("QueryEnclavePrivateState height=%d", in.Height))

	// Attest the CALLER before reading a byte of private state.  This is the check that matters:
	// it is what stops an untrusted enclave from requesting the AML window and identity index.
	// verifyRemoteReport ends at getEnclaveIdentity, which requires the caller's measurement to be
	// ACTIVE on chain -- and because identities are keyed by measurement rather than by node, a
	// brand-new joiner running a released binary passes with no prior registration.
	if !s.verifyRemoteReport(in.RemoteReport, strings.Join([]string{in.EnclavePubK}, "|")) {
		c.LoggerError(logger, "QueryEnclavePrivateState: caller's remote report did not verify")
		return nil, types.ErrRemoteReportNotVerified
	}

	if in.Height <= 0 {
		return nil, fmt.Errorf("private-state transfer requires a specific height")
	}

	cursor, err := decodeCursor(in.Cursor)
	if err != nil {
		return nil, err
	}

	// The window value comes from the REQUESTER, and it has to: policy reaches an enclave
	// per-message from the chain (SuspiciousPolicyFromParams), so an enclave asked for a historical
	// view holds no window of its own.  The requester reads it from the chain state it just
	// restored at H, which is also the correct value if governance retuned the window since.
	//
	// Clamped UP to the compiled-in default, never down.  Over-pruning drops live entries and
	// forks; under-pruning is harmless because the receiver's first scan of a wallet prunes again
	// anyway.  A zero here means "unset", matching SuspiciousPolicyFromParams' own convention.
	window := in.WindowSeconds
	if window <= 0 || window < int64(c.DefaultSuspiciousWindow.Seconds()) {
		window = int64(c.DefaultSuspiciousWindow.Seconds())
	}
	cutoff := int64(0)
	if in.BlockTimeUnix > 0 {
		cutoff = in.BlockTimeUnix - window
	}

	budget := int(in.MaxBytes)
	if budget <= 0 || budget > privateStatePageTargetBytes {
		budget = privateStatePageTargetBytes
	}

	var page *types.EnclavePrivateStatePage
	err = s.withHeightPinned(in.Height, func() error {
		var e error
		page, e = s.buildPrivateStatePage(in.Height, cutoff, cursor, budget)
		return e
	})
	if err != nil {
		return nil, err
	}

	plain, err := page.Marshal()
	if err != nil {
		return nil, err
	}
	zipped, err := gzipBytes(plain)
	if err != nil {
		return nil, err
	}
	enc := c.BEncrypt(in.EnclavePubK, zipped)

	if len(enc) > privateStatePageHardLimitBytes {
		// unreachable given the plaintext budget; if it ever fires, the budget reasoning is wrong
		// and a truncated transfer would be worse than a refusal
		return nil, fmt.Errorf("encrypted private-state page is %d bytes, above the %d byte transport limit", len(enc), privateStatePageHardLimitBytes)
	}

	report, err := s.getRemoteReport(strings.Join([]string{string(enc)}, "|"))
	if err != nil {
		return nil, err
	}

	c.LoggerInfo(logger, fmt.Sprintf("served private-state page: height=%d rows=%d plain=%d gzip=%d enc=%d done=%v",
		in.Height, len(page.Rows), len(plain), len(zipped), len(enc), page.Done))

	return &types.QueryEnclavePrivateStateResponse{
		RemoteReport:            report,
		EncPrivateStatePagePubK: enc,
	}, nil
}

// buildPrivateStatePage walks tables from the cursor until the plaintext budget is reached.
// Callers must already have pinned the height.
func (s *qadenaServer) buildPrivateStatePage(height, cutoff int64, cursor privateStateCursor, budget int) (*types.EnclavePrivateStatePage, error) {
	page := &types.EnclavePrivateStatePage{Height: height}
	used := 0

	for ti := cursor.Table; ti < len(privateStateTables); ti++ {
		tbl := privateStateTables[ti]
		store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(tbl.prefix))

		// Resume by re-sealing the cursor's plaintext key with OUR secret and starting there.  The
		// row at that exact key was already sent, so it is skipped below.
		var start []byte
		resumeKey := ""
		if ti == cursor.Table && cursor.Key != "" {
			resumeKey = cursor.Key
			start = s.MustSealStable(EnclaveKeyKey(cursor.Key))
		}

		// The resume point must be the last key emitted FROM THIS TABLE, not the last key in the
		// page.  Those differ whenever a page ends just as a new table begins, and using the page's
		// last key would seek into the new table at a position derived from the previous table's
		// key -- skipping an arbitrary prefix of it, or all of it.  Empty means "start of table".
		lastKeyInTable := ""

		itr := store.Iterator(start, nil)
		for ; itr.Valid(); itr.Next() {
			plainKey := stripKeySeparator(s.MustUnsealStable(itr.Key()))
			if plainKey == resumeKey {
				continue // already delivered on the previous page
			}

			value, include, err := s.decodePrivateStateRow(tbl, itr.Value(), cutoff)
			if err != nil {
				itr.Close()
				return nil, fmt.Errorf("table %s key %q: %w", tbl.prefix, plainKey, err)
			}
			if !include {
				continue // e.g. an AML row that is entirely outside the window
			}

			rowSize := len(tbl.prefix) + len(plainKey) + len(value)
			if rowSize > privateStateMaxRowBytes {
				itr.Close()
				return nil, fmt.Errorf("table %s key %q is %d bytes, above the %d byte per-row limit: this row cannot be transferred, and omitting it would leave the joiner silently short",
					tbl.prefix, plainKey, rowSize, privateStateMaxRowBytes)
			}

			// Over budget -- stop and hand back a cursor.  Except when nothing has been added yet:
			// a single oversized row must still make progress, or the transfer stalls forever on it.
			if used+rowSize > budget && len(page.Rows) > 0 {
				itr.Close()
				page.NextCursor = encodeCursor(privateStateCursor{Table: ti, Key: lastKeyInTable})
				page.Done = false
				return page, nil
			}

			page.Rows = append(page.Rows, &types.EnclavePrivateStateRow{
				Table: tbl.prefix,
				Key:   plainKey,
				Value: value,
			})
			used += rowSize
			lastKeyInTable = plainKey
		}
		itr.Close()
	}

	page.Done = true
	return page, nil
}

// decodePrivateStateRow unseals a stored value and returns its PLAINTEXT marshalled form.
// include is false for rows that carry nothing worth sending.
func (s *qadenaServer) decodePrivateStateRow(tbl privateStateTable, stored []byte, cutoff int64) (value []byte, include bool, err error) {
	switch tbl.kind {
	case kindSealedString:
		var v types.EnclaveStoreString
		s.Cdc.MustUnmarshal(s.MustUnseal(stored), &v)
		b, e := v.Marshal()
		return b, true, e

	case kindIdentityHistory:
		var v types.EncryptableCredentialIdentityHistory
		s.Cdc.MustUnmarshal(s.MustUnseal(stored), &v)
		b, e := v.Marshal()
		return b, true, e

	case kindScanHistory:
		var v types.EncryptableScanTransferHistory
		s.Cdc.MustUnmarshal(s.MustUnseal(stored), &v)
		// Prune to the window before sending.  Pruning is LAZY on the write path -- a wallet's
		// stale entries survive until it next sends -- so an untouched table accumulates one row
		// per wallet that has EVER sent, most of them entirely dead.  Those rows cannot affect any
		// future verdict (block time only moves forward, and the scan prunes before reading), so
		// sending them would be pure cost, and on an aged chain they dominate the payload.
		if cutoff > 0 {
			v.Transfers = c.PruneExpired(v.Transfers, cutoff)
		}
		if len(v.Transfers) == 0 {
			return nil, false, nil
		}
		b, e := v.Marshal()
		return b, true, e
	}
	return nil, false, fmt.Errorf("unknown private-state table kind %d", tbl.kind)
}

// ---- receiver: apply rows ----

func (s *qadenaServer) applyPrivateStateRow(row *types.EnclavePrivateStateRow) error {
	switch row.Table {
	case EnclaveScanTransferHistoryKeyPrefix:
		var v types.EncryptableScanTransferHistory
		if err := v.Unmarshal(row.Value); err != nil {
			return err
		}
		s.setScanTransferHistory(row.Key, v)

	case EnclaveCredentialHashKeyPrefix:
		var v types.EnclaveStoreString
		if err := v.Unmarshal(row.Value); err != nil {
			return err
		}
		s.setCredentialByHash(row.Key, v.GetS())

	case EnclaveCredentialHashesByCredentialIDKeyPrefix:
		var v types.EncryptableCredentialIdentityHistory
		if err := v.Unmarshal(row.Value); err != nil {
			return err
		}
		s.setCredentialIdentityHistory(row.Key, v)

	case EnclaveProtectSubWalletIDByOriginalWalletIDKeyPrefix:
		var v types.EnclaveStoreString
		if err := v.Unmarshal(row.Value); err != nil {
			return err
		}
		s.setProtectSubWalletIDByOriginalWalletID(row.Key, v.GetS())

	case EnclaveRecoverOriginalWalletIDByNewWalletIDKeyPrefix:
		var v types.EnclaveStoreString
		if err := v.Unmarshal(row.Value); err != nil {
			return err
		}
		s.setRecoverOriginalWalletIDByNewWalletID(row.Key, v.GetS())

	default:
		// A peer on a newer build sending a table this one does not know.  Refuse: accepting the
		// rest would produce a store that looks complete and is not.
		return fmt.Errorf("peer sent private-state table %q, which this enclave does not know how to import", row.Table)
	}
	return nil
}

// privateStateSyncHeight reports a completed import's height, or 0.
func (s *qadenaServer) privateStateSyncHeight() int64 {
	b, err := s.MetaDB.Get([]byte(qmetaPrivateSyncHeightKey))
	if err != nil {
		panic("qadena enclave: cannot read private-sync marker: " + err.Error())
	}
	if len(b) == 0 {
		return 0
	}
	var h int64
	if _, err := fmt.Sscanf(string(b), "%d", &h); err != nil {
		panic("qadena enclave: corrupt private-sync marker: " + err.Error())
	}
	return h
}

func (s *qadenaServer) setPrivateStateSyncHeight(height int64) {
	if err := s.MetaDB.SetSync([]byte(qmetaPrivateSyncHeightKey), []byte(fmt.Sprintf("%d", height))); err != nil {
		panic("qadena enclave: cannot record private-sync marker: " + err.Error())
	}
}

// privateStateTablesAreEmpty reports whether every transferred table is empty, which is the only
// state an import may run against.
func (s *qadenaServer) privateStateTablesAreEmpty() (empty bool, nonEmpty string) {
	for _, tbl := range privateStateTables {
		store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(tbl.prefix))
		itr := store.Iterator(nil, nil)
		valid := itr.Valid()
		itr.Close()
		if valid {
			return false, tbl.prefix
		}
	}
	return true, ""
}

// peerQueryClient builds a chain query client aimed at one peer, the same way getSSPrivK does when
// it goes looking for secret shares.  Endpoints may be given bare ("192.168.1.5") or complete
// ("tcp://192.168.1.5:26657").
func (s *qadenaServer) peerQueryClient(peer string) (types.QueryClient, error) {
	node := peer
	if !strings.Contains(node, "://") {
		node = "tcp://" + node
		if !strings.Contains(node[6:], ":") {
			node += ":26657"
		}
	}
	RootCmd.Flags().Set(flags.FlagNode, node)
	queryClientCtx, err := client.ReadPersistentCommandFlags(clientCtx, RootCmd.Flags())
	if err != nil {
		return nil, err
	}
	return types.NewQueryClient(queryClientCtx), nil
}

// SyncPrivateState pulls the private tables at a height from a peer and commits them atomically.
//
// Runs from EnclaveBeginBlock AFTER enclaveSynchronizeStores, and that order is load-bearing twice
// over: the push seeds EnclaveIdentity, without which no peer's attestation can be checked, and
// IntervalPublicKeyID, without which no peer can be located.  It must also complete BEFORE any
// transaction of H+1 executes, because the AML window is read during execution.
func (s *qadenaServer) SyncPrivateState(goCtx context.Context, in *types.MsgSyncPrivateState) (*types.SyncPrivateStateReply, error) {
	if in.Height <= 0 {
		return nil, fmt.Errorf("private-state sync requires a specific height")
	}

	// Already done?  Idempotent by height.
	if h := s.privateStateSyncHeight(); h != 0 {
		if h == in.Height {
			c.LoggerInfo(logger, fmt.Sprintf("private state already imported at height %d", h))
			return &types.SyncPrivateStateReply{Status: true, Height: h}, nil
		}
		return nil, fmt.Errorf("this enclave already imported private state at height %d; importing again at %d would mix two snapshots", h, in.Height)
	}

	progress, err := s.privateStateProgress()
	if err != nil {
		return nil, err
	}

	switch {
	case progress != nil && progress.Height == in.Height:
		// resuming an interrupted import; rows are expected to be present already
		c.LoggerInfo(logger, fmt.Sprintf("resuming private-state import at height %d after %d rows over %d pages", in.Height, progress.Rows, progress.Pages))

	case progress != nil:
		return nil, fmt.Errorf("an unfinished private-state import for height %d is recorded, but height %d was requested; the partial rows must be discarded before importing a different snapshot", progress.Height, in.Height)

	default:
		// Fresh import.  Existing rows without a marker mean state of unknown provenance, and
		// overwriting them would hide a real divergence.
		if empty, table := s.privateStateTablesAreEmpty(); !empty {
			return nil, fmt.Errorf("refusing to import private state: %s already holds rows but no import marker is present, so this enclave's state is of unknown provenance", table)
		}

		// A non-empty outbox means undelivered rows for heights at or below H.  The peer's
		// equivalents were already drained into chain state, which our snapshot contains, so
		// delivering ours at H+1 would deliver them twice.
		if ob := exportOutbox(s); len(ob.Wallets)+len(ob.ChangedCredentials)+len(ob.RemovedCredentials)+len(ob.RecoverKeys)+len(ob.Suspicious) > 0 {
			return nil, fmt.Errorf("refusing to import private state: this enclave's outbox is not empty, and delivering those rows after an import would double-deliver what the snapshot already contains")
		}
	}

	if len(in.Peers) == 0 {
		return nil, fmt.Errorf("no peers supplied to fetch private state at height %d", in.Height)
	}

	var lastErr error
	for _, peer := range in.Peers {
		err := s.fetchPrivateStateFromPeer(peer, in)
		if err != nil {
			c.LoggerError(logger, "private-state fetch from "+peer+" failed: "+err.Error())
			lastErr = err
			// Pages already committed stay: they are height-pinned content, identical on every
			// correct peer, so resuming against a different one is sound.  What is NOT carried
			// across is the uncommitted tail, which is dropped with the cache.
			s.CacheCtx, s.CacheCtxWrite = s.ServerCtx.CacheContext()
			continue
		}

		p, _ := s.privateStateProgress()
		rows, pages := 0, 0
		if p != nil {
			rows, pages = p.Rows, p.Pages
		}
		if err := s.finishPrivateStateImport(in.Height); err != nil {
			return nil, err
		}
		c.LoggerInfo(logger, fmt.Sprintf("imported private state at height %d from %s: %d rows over %d pages", in.Height, peer, rows, pages))
		return &types.SyncPrivateStateReply{
			Status: true, Height: in.Height, Rows: uint64(rows), Pages: uint32(pages), ServedBy: peer,
		}, nil
	}

	return nil, fmt.Errorf("no peer could serve private state at height %d (last error: %v)", in.Height, lastErr)
}

// fetchPrivateStateFromPeer pulls pages from one peer, COMMITTING EACH ONE before requesting the
// next so that live memory stays bounded by a single page rather than by the size of the whole
// private state.
func (s *qadenaServer) fetchPrivateStateFromPeer(peer string, in *types.MsgSyncPrivateState) (err error) {
	queryClient, err := s.peerQueryClient(peer)
	if err != nil {
		return err
	}

	progress, err := s.privateStateProgress()
	if err != nil {
		return err
	}
	if progress == nil {
		progress = &privateStateProgress{Height: in.Height}
	}
	cursor := progress.Cursor
	rows, pages := progress.Rows, progress.Pages

	for {
		report, err := s.getRemoteReport(strings.Join([]string{s.getPrivateEnclaveParamsEnclavePubK()}, "|"))
		if err != nil {
			return err
		}

		res, err := queryClient.EnclavePrivateState(context.Background(), &types.QueryEnclavePrivateStateRequest{
			RemoteReport:  report,
			EnclavePubK:   s.getPrivateEnclaveParamsEnclavePubK(),
			Height:        in.Height,
			WindowSeconds: in.WindowSeconds,
			BlockTimeUnix: in.BlockTimeUnix,
			Cursor:        cursor,
			MaxBytes:      privateStatePageTargetBytes,
		})
		if err != nil {
			return err
		}

		// Verify the PEER before decrypting, bound to the exact ciphertext received.  Unlike
		// sync-enclave -- which runs before this node has any chain state and therefore cannot do
		// this -- the EnclaveIdentity mirror is populated by the time we get here, so the full
		// chain-anchored check is available and is what we use.  An unbound check would let a
		// genuine report harvested from a real enclave be paired with a substituted payload.
		if !s.verifyRemoteReport(res.GetRemoteReport(), strings.Join([]string{string(res.GetEncPrivateStatePagePubK())}, "|")) {
			return fmt.Errorf("peer %s returned a private-state page whose remote report did not verify", peer)
		}

		zipped := c.BDecrypt(s.getPrivateEnclaveParamsEnclavePrivK(), res.GetEncPrivateStatePagePubK())
		plain, err := gunzipBytes(zipped)
		if err != nil {
			return fmt.Errorf("peer %s returned an undecompressable page: %w", peer, err)
		}

		var page types.EnclavePrivateStatePage
		if err := page.Unmarshal(plain); err != nil {
			return fmt.Errorf("peer %s returned an unparseable page: %w", peer, err)
		}
		if page.Height != in.Height {
			return fmt.Errorf("peer %s served height %d when asked for %d", peer, page.Height, in.Height)
		}

		for _, row := range page.Rows {
			if err := s.applyPrivateStateRow(row); err != nil {
				return err
			}
			rows++
		}
		pages++

		if !page.Done && len(page.NextCursor) == 0 {
			return fmt.Errorf("peer %s returned an unfinished page with no cursor", peer)
		}
		cursor = page.NextCursor

		// Make this page durable and release its memory before asking for the next.  Without this
		// the whole private state accumulates in the transaction cache, which is what turns a large
		// import into an out-of-memory inside the enclave.
		if err := s.commitPrivateStatePage(privateStateProgress{
			Height: in.Height, Cursor: cursor, Rows: rows, Pages: pages,
		}); err != nil {
			return err
		}

		if page.Done {
			return nil
		}
	}
}

// commitPrivateStatePage promotes one page's rows, persists them, records the resume point, and
// hands back a FRESH empty cache so the next page starts from nothing.
//
// The IAVL commit here is out-of-band: no qmeta/hv entry is written, so the version belongs to no
// height.  That is a pre-existing, documented object (SyncEnclave commits the same way) and it is
// what keeps rollback honest -- there is no height to roll back to, because these rows were never
// produced by executing a block.
func (s *qadenaServer) commitPrivateStatePage(progress privateStateProgress) error {
	cms, ok := s.ServerCtx.MultiStore().(storetypes.CommitMultiStore)
	if !ok {
		return fmt.Errorf("enclave multistore is not a CommitMultiStore; cannot commit the private-state import")
	}

	s.commitCache()
	cms.Commit()

	// Written AFTER the commit.  The other order would let a crash in between record progress past
	// rows that were never persisted, which on resume would skip them silently -- exactly the kind
	// of quiet gap this whole mechanism exists to prevent.  This order can only ever re-apply a
	// page, which is harmless: every write is a whole-row Set, never an append.
	if err := s.setPrivateStateProgress(progress); err != nil {
		return err
	}

	s.CacheCtx, s.CacheCtxWrite = s.ServerCtx.CacheContext()
	return nil
}

func (s *qadenaServer) privateStateProgress() (*privateStateProgress, error) {
	b, err := s.MetaDB.Get([]byte(qmetaPrivateSyncProgressKey))
	if err != nil {
		return nil, fmt.Errorf("cannot read the private-state import progress marker: %w", err)
	}
	if len(b) == 0 {
		return nil, nil
	}
	var p privateStateProgress
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("corrupt private-state import progress marker: %w", err)
	}
	return &p, nil
}

func (s *qadenaServer) setPrivateStateProgress(p privateStateProgress) error {
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return s.MetaDB.SetSync([]byte(qmetaPrivateSyncProgressKey), b)
}

// finishPrivateStateImport marks the import complete and clears the resume point.  Only after this
// does the enclave consider itself to hold usable private state.
func (s *qadenaServer) finishPrivateStateImport(height int64) error {
	s.setPrivateStateSyncHeight(height)
	if err := s.MetaDB.DeleteSync([]byte(qmetaPrivateSyncProgressKey)); err != nil {
		return fmt.Errorf("cannot clear the private-state import progress marker: %w", err)
	}
	return nil
}
