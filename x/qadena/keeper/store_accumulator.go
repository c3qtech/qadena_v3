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
