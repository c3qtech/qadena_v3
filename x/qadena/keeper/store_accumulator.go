package keeper

// The chain half of the shadow accumulators.  The enclave half is cmd/qadenad_enclave/
// enclave_accumulator.go, and both fold rows with the SAME helper in x/qadena/common -- one
// implementation, so the two sides cannot drift in formulation while appearing to agree.
//
// RUNS ALONGSIDE THE SCAN.  StoreHashByKVStoreService keeps scanning and keeps being the answer;
// this only reports whether the maintained value agrees.  See the enclave file for why an
// accumulator is treated as a claim rather than a fact until it has been quiet for a long time.

import (
	"context"
	"fmt"
	"sort"

	"cosmossdk.io/store/prefix"
	"github.com/cosmos/cosmos-sdk/runtime"
	sdk "github.com/cosmos/cosmos-sdk/types"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"
	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

// StoreAccumulatorKeyPrefix holds one row per accumulated prefix, keyed by that prefix.
//
// NOT one of the accumulated prefixes, or writing it would change the table it summarises.
const StoreAccumulatorKeyPrefix = "StoreAccumulator/value/"

func (k Keeper) accumulatorStore(ctx context.Context) prefix.Store {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	return prefix.NewStore(storeAdapter, types.KeyPrefix(StoreAccumulatorKeyPrefix))
}

func (k Keeper) tableStore(ctx context.Context, pfx string) prefix.Store {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	return prefix.NewStore(storeAdapter, types.KeyPrefix(pfx))
}

// LoadStoreAccumulator returns the stored value and whether one exists.  Absent is not zero: an
// empty table accumulates to zero legitimately, and a missing accumulator means "unknown".
func (k Keeper) LoadStoreAccumulator(ctx context.Context, pfx string) (c.StoreAccumulator, bool) {
	return c.ParseStoreAccumulator(k.accumulatorStore(ctx).Get([]byte(pfx)))
}

func (k Keeper) saveStoreAccumulator(ctx context.Context, pfx string, acc c.StoreAccumulator) {
	k.accumulatorStore(ctx).Set([]byte(pfx), c.StoreAccumulatorBytes(acc))
}

// AccumulateWrite folds one row change in.  CALL BEFORE THE STORE WRITE: an overwrite has to
// subtract the row's previous value, and after the write that value is gone.  newValue nil = delete.
//
// A no-op until the accumulator has been established, because genesis and the mirror push write in
// bulk and a value covering only "rows seen since startup" would be worse than none.
func (k Keeper) AccumulateWrite(ctx context.Context, pfx string, key []byte, newValue []byte) {
	c.AccumulateRowWrite(k.accumulatorStore(ctx), k.tableStore(ctx, pfx), pfx, key, newValue)
}

// EnsureStoreAccumulator establishes a prefix's accumulator by scanning, if it has none.  This is
// the path for rows that arrived without passing through a setter -- genesis, a state-sync restore,
// a bulk seed -- which is the same gap that left the iavl fast index silently empty.
func (k Keeper) EnsureStoreAccumulator(ctx context.Context, pfx string) c.StoreAccumulator {
	if acc, ok := k.LoadStoreAccumulator(ctx, pfx); ok {
		return acc
	}
	acc, rows := c.AccumulatorFromPrefixStore(k.tableStore(ctx, pfx))
	k.saveStoreAccumulator(ctx, pfx, acc)
	if sdkctx, ok := ctx.(sdk.Context); ok {
		c.ContextInfo(sdkctx, "ACCUMULATOR established "+accumulatorLog(pfx, rows, acc))
	}
	return acc
}

// accumulatorLog matches the enclave's format deliberately (cmd/qadenad_enclave/
// enclave_accumulator.go).  The whole purpose of these two accumulators is to be COMPARED, so their
// log lines have to be greppable and diffable side by side -- same store, same row count, same
// digest, or the two halves disagree.
func accumulatorLog(pfx string, rows int, acc c.StoreAccumulator) string {
	return fmt.Sprintf("key=%s rows=%d acc=%s", pfx, rows, c.AccumulatorHex(acc))
}

// maintainStoreAccumulators establishes any missing accumulator, for every mirrored store, once
// per block -- the chain-side twin of the enclave's maintainAccumulators, called from
// EnclaveEndBlock.  After the first block each pass costs one store Get per prefix.
//
// THIS IS THE ACTIVATION POINT, and it is CONSENSUS-VISIBLE: the rows it writes live in the
// qadena module store, which feeds the app hash.  The arithmetic is deterministic -- every node
// running this code computes byte-identical rows from byte-identical writes -- so upgraded nodes
// agree with each other, but they disagree with un-upgraded ones from the first block after the
// swap.  All nodes of a chain must cross this change together.
//
// dsvs's AuthorizedSignatory is deliberately absent: that store lives in the dsvs module's own
// store space, which this keeper cannot reach; the dsvs keeper establishes it from its own
// per-block hook.
func (k Keeper) maintainStoreAccumulators(sdkctx sdk.Context) {
	// Sorted, not ranged: map order varies per process, and while the WRITE-SET is identical
	// either way (commits sort by key), nobody should have to prove that to review this.
	prefixes := make([]string, 0, len(mirroredStores))
	for pfx := range mirroredStores {
		prefixes = append(prefixes, pfx)
	}
	sort.Strings(prefixes)
	for _, pfx := range prefixes {
		k.EnsureStoreAccumulator(sdkctx, pfx)
	}
}

// fetchEnclaveAccumulators calls the accumulator seam (GetStoreAccumulators) and returns the
// enclave's current values by store key.  Advisory in phase 1: any failure returns nil and the
// caller proceeds on scans alone -- an old enclave that lacks the RPC must not break sync.
func (k Keeper) fetchEnclaveAccumulators(sdkctx sdk.Context) map[string][]byte {
	ctx, cancel := enclaveExecContext()
	defer cancel()

	r, err := EnclaveGRPCClient.GetStoreAccumulators(ctx, &types.MsgGetStoreAccumulators{})
	if err != nil {
		c.ContextError(sdkctx, "Qadena: GetStoreAccumulators unavailable (proceeding on scans alone): "+err.Error())
		return nil
	}
	out := map[string][]byte{}
	for _, e := range r.GetAccumulators() {
		if e.GetPresent() {
			out[e.GetKey()] = e.GetAcc()
		}
	}
	return out
}

// compareAccumulatorSeam is the SIDE-BY-SIDE check for one store: does the acc-to-acc verdict
// agree with the scan-to-scan verdict, taken at the same instant?
//
// This is phase 1 of replacing the scans (backlog items 44/46): the scan verdict remains the one
// that acts; the accumulator verdict only reports.  The one line that matters is the DISAGREES
// one -- the two mechanisms claiming different answers about the same store at the same moment
// means one of them is wrong, and that must be understood before the cheap one is ever trusted.
//
// CALL WITH VERDICTS FROM THE SAME INSTANT: both replies captured before any seeding, or a
// successful seed makes the accumulators agree while the scans (sampled pre-seed) did not, and
// the alarm fires on a phantom.
func (k Keeper) compareAccumulatorSeam(sdkctx sdk.Context, key string, enclaveAccs map[string][]byte, scanAgree bool) {
	if enclaveAccs == nil {
		return // seam unavailable; nothing to compare
	}
	encAcc, ok := enclaveAccs[key]
	if !ok {
		c.ContextError(sdkctx, "Qadena: ACC-SEAM enclave returned no accumulator for key="+key)
		return
	}
	chainAcc, ok := k.LoadStoreAccumulator(sdkctx, key)
	if !ok {
		// Cannot happen after CompareStoreAccumulator ran for this key (it establishes on
		// absence), so reaching here means the call order in the sync loop changed.
		c.ContextError(sdkctx, "Qadena: ACC-SEAM chain has no accumulator for key="+key+" -- call order bug")
		return
	}

	accAgree := string(chainAcc[:]) == string(encAcc)
	if accAgree != scanAgree {
		c.ContextError(sdkctx, fmt.Sprintf(
			"Qadena: ACC-SEAM VERDICT DISAGREES WITH SCAN key=%s accAgree=%t scanAgree=%t "+
				"chainAcc=%s enclaveAcc=%x -- one mechanism is wrong; do not trust the accumulator path until this is understood",
			key, accAgree, scanAgree, c.AccumulatorHex(chainAcc), encAcc))
		return
	}
	c.ContextDebug(sdkctx, fmt.Sprintf("Qadena: ACC-SEAM agrees with scan key=%s inSync=%t", key, accAgree))
}

// CompareStoreAccumulator is the shadow check, run where the chain already scans.
//
// Unlike the enclave's, this one MAY write -- it is reached from block execution rather than from a
// read-only RPC -- so it repairs immediately instead of deferring.  A mismatch logs at ERROR, which
// is visible at info level exactly as OUT-OF-SYNC is, because it means some write path is not
// maintaining the accumulator and that has to be known before this is trusted.
func (k Keeper) CompareStoreAccumulator(ctx sdk.Context, pfx string) {
	scanned, rows := c.AccumulatorFromPrefixStore(k.tableStore(ctx, pfx))

	acc, ok := k.LoadStoreAccumulator(ctx, pfx)
	if !ok {
		c.ContextInfo(ctx, "ACCUMULATOR established "+accumulatorLog(pfx, rows, scanned))
		k.saveStoreAccumulator(ctx, pfx, scanned)
		return
	}
	if acc != scanned {
		c.ContextError(ctx, "ACCUMULATOR MISMATCH key="+pfx+
			" rows="+fmt.Sprint(rows)+
			" maintained="+c.AccumulatorHex(acc)+
			" scanned="+c.AccumulatorHex(scanned)+
			" -- a write path is not maintaining it; re-seeding from the scan")
		k.saveStoreAccumulator(ctx, pfx, scanned)
		return
	}

	// Debug for the same reason as the enclave's: it runs wherever the chain already scans, so at
	// info it would be noise -- but without it, silence cannot be told apart from never having run.
	c.ContextDebug(ctx, "ACCUMULATOR ok "+accumulatorLog(pfx, rows, acc))
}
