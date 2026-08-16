package keeper

// Paged chain->enclave seeding -- the sending half.  The enclave half is
// cmd/qadenad_enclave/enclave_seed_page.go.
//
// This replaces, for every mirrored store, the shape:
//
//	rows := k.GetAllX(sdkctx)          // whole table materialised in memory
//	for _, row := range rows {         // one gRPC call per row
//	        k.EnclaveClientSetX(sdkctx, row)
//	}
//
// On a state-synced joiner the big tables run to five figures, so that was five figures of round
// trips per table and a full copy of each table held on the heap to produce them.
//
// Three things get cheaper, and it is worth being precise about which, because the fourth does not:
//
//  1. ROUND TRIPS: ~10k per table becomes ~1 per megabyte.  This is the large one, though less
//     dramatic than it sounds -- the transport is a unix domain socket (see enclave.go:8329), so
//     each trip was tens of microseconds, not a network hop.  What actually dominated was the
//     per-call proto marshal, HTTP/2 framing and handler dispatch, ~10k times over.
//  2. CHAIN MEMORY: an iterator, so no table is ever fully resident.  Peak becomes one page.
//  3. SERIALISATION: rows go to the wire exactly as they sit in the store, skipping the
//     unmarshal-into-a-struct-then-marshal-it-again round trip GetAllX forced.  See rowsAreSentRaw.
//  4. NOT the per-row handler work inside the enclave, which is untouched by design and which for
//     ProtectKey and RecoverKey -- a vshare decrypt and a network reconstruction of a historical
//     interval key -- still dominates everything above.
//
// ENCLAVE MEMORY MOVES THE WRONG WAY HERE, mildly, and that is the trade being made.  The enclave
// used to hold one row at a time and now holds a page: the request buffer plus its unmarshalled
// [][]byte, so roughly twice the page budget, inside an EPC measured in tens of megabytes.  A
// megabyte is the same page size the private-state sync already runs at (see
// privateStatePageTargetBytes), which is the evidence that this size is comfortable there.

import (
	"fmt"
	"os"
	"strconv"

	"cosmossdk.io/store/prefix"
	storetypes "cosmossdk.io/store/types"
	"github.com/cosmos/cosmos-sdk/runtime"
	sdk "github.com/cosmos/cosmos-sdk/types"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"
	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

// mirrorSeedPageTargetBytes budgets the ROW PAYLOAD of a page.
//
// Deliberately well under the 4 MiB grpc-go default that both ends run at unmodified, because the
// budget is not the whole message: the key string, the per-row framing accounted for below, and
// gRPC's own overhead all sit on top.  The margin is wide enough that none of that needs to be
// exact.
//
// OVERRIDABLE DOWNWARD via QADENA_PAGE_BUDGET, chain-side only, for forced-paging runs.  Real
// tables are ~1000x too small to page at 1 MiB, so without this the multi-page branches only ever
// run in unit tests; a debug node started with a few-KiB budget pages constantly under ordinary
// regression traffic instead.  Safe on three counts: page size is transport batching and never
// reaches state; the enclave accepts whatever page sizes arrive (SeedStorePage has no floor, and
// outboxPageBudget clamps only values that exceed ITS ceiling); and values above the default are
// refused here so the knob cannot push a page toward the 4 MiB transport limit.  This mirrors how
// TestPrivateStateTransferPagesFaithfully proves the enclave-to-enclave pager -- shrink the
// budget, force many pages, require identical results.
var mirrorSeedPageTargetBytes = pageBudgetFromEnv(1 << 20)

func pageBudgetFromEnv(def int) int {
	if v := os.Getenv("QADENA_PAGE_BUDGET"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n < def {
			return n
		}
	}
	return def
}

// drainMaxBytes rides each outbox drain request.  0 means "the enclave's own default"; under a
// forced-paging run it carries the shrunken budget, which the enclave honours because small values
// pass its clamp untouched.
var drainMaxBytes = uint32(func() int {
	if b := pageBudgetFromEnv(1 << 20); b < 1<<20 {
		return b
	}
	return 0
}())

// mirrorSeedRowOverheadBytes covers each row's protobuf field tag and length varint.  Counted so
// that a page of many small rows -- IntervalPublicKeyID, say -- cannot drift over the budget
// through framing alone.
const mirrorSeedRowOverheadBytes = 8

// rowsAreSentRaw records why a page may carry the stored bytes rather than re-encoded structs.
//
// Every GetAllX this replaces was a plain `cdc.MustUnmarshal(iterator.Value(), &val)` into the same
// type the enclave's handler takes, and every EnclaveClientSetX passed that value through
// untouched.  So the chain's decode and re-encode was a round trip that could only return what it
// started with, and dropping it changes nothing the enclave observes.
//
// This is worth stating explicitly because the encodings are NOT always identical: SetWalletNoEnclave
// stores a StableWallet while GetAllWallet reads those same bytes back as a Wallet.  Sending the
// stored bytes is still correct -- the enclave decodes them as a Wallet, which is precisely what
// GetAllWallet did -- but it means the rule is "decode as the handler's type", not "the stored type
// is the wire type".  A store that ever needs a real conversion rather than a reinterpretation must
// not use this path.
const rowsAreSentRaw = true

// mirroredStores is the set of stores the chain seeds into the enclave.
//
// It must agree with GetStoreHash's list on the enclave side and with the enclave's seedHandlers
// map.  A store in one and not the others is not a no-op: a hash with no seeder reports OUT-OF-SYNC
// forever and never repairs, and a seeder with no hash is never invoked.
//
// PioneerJar is the standing example of getting this wrong.  SetPioneerJar had always forwarded
// writes to the enclave, so the mirror looked complete -- but the store was absent from this set,
// so a node that did not EXECUTE the block creating the jar never received it.  A state-synced
// joiner sat at 0 rows against the primary's 1, with the row present in its own chain store the
// entire time.  Everything needed already existed; only the membership was missing.
var mirroredStores = map[string]bool{
	types.WalletKeyPrefix:              true,
	types.CredentialKeyPrefix:          true,
	types.PublicKeyKeyPrefix:           true,
	types.PioneerJarKeyPrefix:          true,
	types.JarRegulatorKeyPrefix:        true,
	types.IntervalPublicKeyIDKeyPrefix: true,
	types.ProtectKeyKeyPrefix:          true,
	types.RecoverKeyKeyPrefix:          true,
	types.EnclaveIdentityKeyPrefix:     true,
}

// seedEnclaveStore streams one mirrored store into the enclave and reports how many rows the
// enclave refused.
//
// The iterator stays open across the gRPC calls.  That is safe here and only here: seeding runs
// from enclaveSynchronizeStores during BeginBlock and reads the chain store while writing only to
// the enclave, so nothing can mutate the store underneath the iteration.
func (k Keeper) seedEnclaveStore(sdkctx sdk.Context, keyPrefix string) (rows int, failed int) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(sdkctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(keyPrefix))
	iterator := storetypes.KVStorePrefixIterator(store, []byte{})
	defer iterator.Close()

	page := &types.MsgSeedStorePage{Key: keyPrefix}
	used := 0
	pages := 0

	flush := func() {
		if len(page.Rows) == 0 {
			return
		}
		failed += k.EnclaveClientSeedStorePage(sdkctx, page)
		pages++
		rows += len(page.Rows)
		// Reused rather than reallocated, which is safe because the call above is UNARY and
		// therefore synchronous: gRPC has serialised the request and received the reply by the time
		// it returns, so nothing holds a reference to these rows any more.  Truncating only resets
		// the slice headers; the row allocations are separate and already on the wire.
		page.Rows = page.Rows[:0]
		used = 0
	}

	for ; iterator.Valid(); iterator.Next() {
		// COPIED, not referenced.  A store iterator's value is only valid until the next Next(),
		// and these have to survive until the page is flushed.
		v := iterator.Value()
		row := make([]byte, len(v))
		copy(row, v)

		// Flushed BEFORE the row is added, so a page can only exceed the budget when one row does
		// so on its own -- in which case it goes alone and the 4 MiB margin absorbs it.
		if used > 0 && used+len(row)+mirrorSeedRowOverheadBytes > mirrorSeedPageTargetBytes {
			flush()
		}
		page.Rows = append(page.Rows, row)
		used += len(row) + mirrorSeedRowOverheadBytes
	}
	flush()

	c.ContextDebug(sdkctx, fmt.Sprintf("Qadena: seeded store key=%s rows=%d pages=%d rejected=%d",
		keyPrefix, rows, pages, failed))
	return rows, failed
}

// EnclaveClientSeedStorePage sends one page and returns the number of rows the enclave rejected.
//
// A transport failure counts the WHOLE page as rejected.  The caller turns any non-zero count into
// a refusal to continue, and a page that never arrived is exactly as missing as one whose rows were
// each refused -- treating it as anything less would let a half-seeded enclave report success.
func (k Keeper) EnclaveClientSeedStorePage(sdkctx sdk.Context, page *types.MsgSeedStorePage) int {
	if sdkctx.IsCheckTx() {
		c.ContextDebug(sdkctx, "SeedStorePage not called in checktx")
		return 0
	}

	ctx, cancel := enclaveExecContext()
	defer cancel()

	r, err := EnclaveGRPCClient.SeedStorePage(ctx, page)
	if err != nil {
		c.ContextError(sdkctx, fmt.Sprintf(
			"error returned by SeedStorePage on enclave for key=%s (%d rows in this page): %s",
			page.GetKey(), len(page.GetRows()), err.Error()))
		return len(page.GetRows())
	}
	return int(r.GetFailed())
}
