package keeper

import (
	"context"

	"qadena/x/dsvs/types"

	"cosmossdk.io/store/prefix"
	storetypes "cosmossdk.io/store/types"
	"github.com/cosmos/cosmos-sdk/runtime"
)

// SetAuthorizedSignatory set a specific authorizedSignatory in the store from its index
func (k Keeper) SetAuthorizedSignatory(ctx context.Context, authorizedSignatory types.AuthorizedSignatory) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.AuthorizedSignatoryKeyPrefix))
	b := k.cdc.MustMarshal(&authorizedSignatory)
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
