package keeper

import (
	"context"

	"github.com/c3qtech/qadena_v3/x/qadena/types"

	"cosmossdk.io/store/prefix"
	storetypes "cosmossdk.io/store/types"
	"github.com/cosmos/cosmos-sdk/runtime"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// SetProtectKey set a specific protectKey in the store from its index
func (k Keeper) SetProtectKey(ctx context.Context, protectKey types.ProtectKey) {
	sdkctx := sdk.UnwrapSDKContext(ctx)
	err := k.EnclaveClientSetProtectKey(sdkctx, protectKey) // forward this to the enclave
	if err != nil {
		c.ContextError(sdkctx, "EnclaveClientSetProtectKey err "+err.Error())
		panic(err.Error())
	}

	c.ContextDebug(sdkctx, "Set Protect Key "+protectKey.WalletID)

	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.ProtectKeyKeyPrefix))
	b := k.cdc.MustMarshal(&protectKey)
	store.Set(types.ProtectKeyKey(
		protectKey.WalletID,
	), b)
}

// GetProtectKey returns a protectKey from its index
func (k Keeper) GetProtectKey(
	ctx context.Context,
	walletID string,

) (val types.ProtectKey, found bool) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.ProtectKeyKeyPrefix))

	b := store.Get(types.ProtectKeyKey(
		walletID,
	))
	if b == nil {
		return val, false
	}

	k.cdc.MustUnmarshal(b, &val)
	return val, true
}

// RemoveProtectKey removes a protectKey from the store
func (k Keeper) RemoveProtectKey(
	ctx context.Context,
	walletID string,

) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.ProtectKeyKeyPrefix))
	store.Delete(types.ProtectKeyKey(
		walletID,
	))
}

// GetAllProtectKey returns all protectKey
func (k Keeper) GetAllProtectKey(ctx context.Context) (list []types.ProtectKey) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.ProtectKeyKeyPrefix))
	iterator := storetypes.KVStorePrefixIterator(store, []byte{})

	defer iterator.Close()

	for ; iterator.Valid(); iterator.Next() {
		var val types.ProtectKey
		k.cdc.MustUnmarshal(iterator.Value(), &val)
		list = append(list, val)
		sdkctx := sdk.UnwrapSDKContext(ctx)
		c.ContextDebug(sdkctx, "Set Protect Key "+val.WalletID)
	}

	return
}
