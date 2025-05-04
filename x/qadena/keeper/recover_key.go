package keeper

import (
	"context"

	"qadena_v3/x/qadena/types"

	"cosmossdk.io/store/prefix"
	storetypes "cosmossdk.io/store/types"
	"github.com/cosmos/cosmos-sdk/runtime"
)

// SetRecoverKey set a specific recoverKey in the store from its index
func (k Keeper) SetRecoverKey(ctx context.Context, recoverKey types.RecoverKey) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.RecoverKeyKeyPrefix))
	b := k.cdc.MustMarshal(&recoverKey)
	store.Set(types.RecoverKeyKey(
		recoverKey.WalletID,
	), b)
}

// GetRecoverKey returns a recoverKey from its index
func (k Keeper) GetRecoverKey(
	ctx context.Context,
	walletID string,

) (val types.RecoverKey, found bool) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.RecoverKeyKeyPrefix))

	b := store.Get(types.RecoverKeyKey(
		walletID,
	))
	if b == nil {
		return val, false
	}

	k.cdc.MustUnmarshal(b, &val)
	return val, true
}

// RemoveRecoverKey removes a recoverKey from the store
func (k Keeper) RemoveRecoverKey(
	ctx context.Context,
	walletID string,

) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.RecoverKeyKeyPrefix))
	store.Delete(types.RecoverKeyKey(
		walletID,
	))
}

// GetAllRecoverKey returns all recoverKey
func (k Keeper) GetAllRecoverKey(ctx context.Context) (list []types.RecoverKey) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.RecoverKeyKeyPrefix))
	iterator := storetypes.KVStorePrefixIterator(store, []byte{})

	defer iterator.Close()

	for ; iterator.Valid(); iterator.Next() {
		var val types.RecoverKey
		k.cdc.MustUnmarshal(iterator.Value(), &val)
		list = append(list, val)
	}

	return
}
