package keeper

// The dsvs module's half of the shadow accumulators.
//
// dsvs owns exactly one mirrored store, AuthorizedSignatory, but it owns it completely: the qadena
// keeper cannot reach it, because the two modules have separate store services.  That is the only
// reason this file exists rather than the qadena keeper covering all ten prefixes -- the arithmetic
// itself is x/qadena/common's, shared with the qadena keeper and the enclave, so there is still one
// implementation of the number and no way for the three to drift while appearing to agree.
//
// AuthorizedSignatory is easy to overlook precisely because it is the odd one out: it appears in
// GetStoreHash's key list alongside nine qadena stores, so it looks like they do, but nothing in
// x/qadena can hook its writes.

import (
	"context"
	"fmt"

	"cosmossdk.io/store/prefix"
	"github.com/cosmos/cosmos-sdk/runtime"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/c3qtech/qadena_v3/x/dsvs/types"
	c "github.com/c3qtech/qadena_v3/x/qadena/common"
)

// StoreAccumulatorKeyPrefix holds one row per accumulated prefix, keyed by that prefix.
//
// Deliberately NOT one of the accumulated prefixes: writing it would change the table it summarises.
const StoreAccumulatorKeyPrefix = "StoreAccumulator/value/"

func (k Keeper) accumulatorStore(ctx context.Context) prefix.Store {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	return prefix.NewStore(storeAdapter, types.KeyPrefix(StoreAccumulatorKeyPrefix))
}

func (k Keeper) tableStore(ctx context.Context, pfx string) prefix.Store {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	return prefix.NewStore(storeAdapter, types.KeyPrefix(pfx))
}

// AccumulateWrite folds one row change in.  CALL BEFORE THE STORE WRITE -- an overwrite has to
// subtract the row's previous value, and after the write that value is gone.  newValue nil = delete.
func (k Keeper) AccumulateWrite(ctx context.Context, pfx string, key []byte, newValue []byte) {
	c.AccumulateRowWrite(k.accumulatorStore(ctx), k.tableStore(ctx, pfx), pfx, key, newValue)
}

// LoadStoreAccumulator returns the stored value and whether one exists.  Absent is not zero: an
// empty table accumulates to zero legitimately, and a missing accumulator means "unknown".
func (k Keeper) LoadStoreAccumulator(ctx context.Context, pfx string) (c.StoreAccumulator, bool) {
	return c.ParseStoreAccumulator(k.accumulatorStore(ctx).Get([]byte(pfx)))
}

// EnsureStoreAccumulator establishes the prefix's accumulator by scanning, if it has none.  This is
// the path for rows that arrived without passing through a setter -- genesis, a state-sync restore,
// a bulk seed -- which is the same gap that left the iavl fast index silently empty.
func (k Keeper) EnsureStoreAccumulator(ctx context.Context, pfx string) c.StoreAccumulator {
	if acc, ok := k.LoadStoreAccumulator(ctx, pfx); ok {
		return acc
	}
	acc, rows := c.AccumulatorFromPrefixStore(k.tableStore(ctx, pfx))
	k.accumulatorStore(ctx).Set([]byte(pfx), c.StoreAccumulatorBytes(acc))
	if sdkctx, ok := ctx.(sdk.Context); ok {
		c.ContextInfo(sdkctx, "ACCUMULATOR established "+accumulatorLog(pfx, rows, acc))
	}
	return acc
}

// accumulatorLog matches the qadena keeper's and the enclave's format exactly -- the three are
// meant to be compared line-for-line.
func accumulatorLog(pfx string, rows int, acc c.StoreAccumulator) string {
	return fmt.Sprintf("key=%s rows=%d acc=%s", pfx, rows, c.AccumulatorHex(acc))
}

// MaintainStoreAccumulators establishes this module's accumulator if it has none, once per block
// from the module's EndBlock -- the dsvs twin of the qadena keeper's maintainStoreAccumulators, in
// this module's own store space, which the qadena keeper cannot reach.  Exported because the
// module package calls it.
func (k Keeper) MaintainStoreAccumulators(sdkctx sdk.Context) {
	k.EnsureStoreAccumulator(sdkctx, types.AuthorizedSignatoryKeyPrefix)

	// The every-Nth-block honesty audit for this module's one store.  Same semantics as the
	// qadena keeper's auditStoreAccumulators: same-context recompute, HALT on mismatch (no
	// repair), deterministic and therefore chain-wide.  25 matches the other side's cadence.
	if sdkctx.BlockHeight()%25 != 0 {
		return
	}
	maintained, ok := k.LoadStoreAccumulator(sdkctx, types.AuthorizedSignatoryKeyPrefix)
	if !ok {
		panic("dsvs: accumulator audit: no maintained value after the maintain pass -- call order bug")
	}
	scanned, rows := c.AccumulatorFromPrefixStore(k.tableStore(sdkctx, types.AuthorizedSignatoryKeyPrefix))
	if maintained != scanned {
		panic(fmt.Sprintf(
			"dsvs: accumulator audit FAILED for %s at height %d: maintained=%s scanned=%s rows=%d -- "+
				"an unhooked write path or corrupted data; halting rather than repairing",
			types.AuthorizedSignatoryKeyPrefix, sdkctx.BlockHeight(), c.AccumulatorHex(maintained), c.AccumulatorHex(scanned), rows))
	}
	c.ContextDebug(sdkctx, fmt.Sprintf("DSVS: accumulator audit clean at height %d", sdkctx.BlockHeight()))
}
