package keeper

import (
	"context"

	"github.com/c3qtech/qadena_v3/x/dsvs/types"

	"cosmossdk.io/store/prefix"
	storetypes "cosmossdk.io/store/types"
	"github.com/cosmos/cosmos-sdk/runtime"
)

// SetAuthorizedSignatory set a specific authorizedSignatory in the store from its index
func (k Keeper) SetAuthorizedSignatory(ctx context.Context, authorizedSignatory types.AuthorizedSignatory) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.AuthorizedSignatoryKeyPrefix))
	b := k.cdc.MustMarshal(&authorizedSignatory)
	// BEFORE the Set: an overwrite has to subtract the previous value, which this read still sees.
	k.AccumulateWrite(ctx, types.AuthorizedSignatoryKeyPrefix, types.AuthorizedSignatoryKey(
		authorizedSignatory.WalletID,
	), b)
	store.Set(types.AuthorizedSignatoryKey(
		authorizedSignatory.WalletID,
	), b)
}

// GetAuthorizedSignatory returns a authorizedSignatory from its index
func (k Keeper) GetAuthorizedSignatory(
	ctx context.Context,
	walletID string,

) (val types.AuthorizedSignatory, found bool) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.AuthorizedSignatoryKeyPrefix))

	b := store.Get(types.AuthorizedSignatoryKey(
		walletID,
	))
	if b == nil {
		return val, false
	}

	k.cdc.MustUnmarshal(b, &val)
	return val, true
}

// RemoveAuthorizedSignatory removes a authorizedSignatory from the store
func (k Keeper) RemoveAuthorizedSignatory(
	ctx context.Context,
	walletID string,

) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.AuthorizedSignatoryKeyPrefix))
	// nil newValue = a delete: the row's contribution is subtracted and nothing added.
	k.AccumulateWrite(ctx, types.AuthorizedSignatoryKeyPrefix, types.AuthorizedSignatoryKey(
		walletID,
	), nil)
	store.Delete(types.AuthorizedSignatoryKey(
		walletID,
	))
}

// GetAllAuthorizedSignatory returns all authorizedSignatory
func (k Keeper) GetAllAuthorizedSignatory(ctx context.Context) (list []types.AuthorizedSignatory) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.AuthorizedSignatoryKeyPrefix))
	iterator := storetypes.KVStorePrefixIterator(store, []byte{})

	defer iterator.Close()

	for ; iterator.Valid(); iterator.Next() {
		var val types.AuthorizedSignatory
		k.cdc.MustUnmarshal(iterator.Value(), &val)
		list = append(list, val)
	}

	return
}
