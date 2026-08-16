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

	"cosmossdk.io/store/prefix"
	"github.com/cosmos/cosmos-sdk/runtime"

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
	acc, _ := c.AccumulatorFromPrefixStore(k.tableStore(ctx, pfx))
	k.accumulatorStore(ctx).Set([]byte(pfx), c.StoreAccumulatorBytes(acc))
	return acc
}
