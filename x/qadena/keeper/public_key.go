package keeper

import (
	"context"

	"qadena/x/qadena/types"

	"cosmossdk.io/store/prefix"
	storetypes "cosmossdk.io/store/types"
	"github.com/cosmos/cosmos-sdk/runtime"

	"qadena/x/qadena/common"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// SetPublicKey set a specific publicKey in the store from its index
func (k Keeper) SetPublicKey(ctx context.Context, publicKey types.PublicKey) {
	sdkctx := sdk.UnwrapSDKContext(ctx)
	err := k.EnclaveClientSetPublicKey(sdkctx, publicKey) // forward this to the enclave
	if err != nil {
		common.ContextError(sdkctx, "EnclaveClientSetPublicKey err "+err.Error())
		panic(err.Error())
	}

	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.PublicKeyKeyPrefix))
	b := k.cdc.MustMarshal(&publicKey)
	store.Set(types.PublicKeyKey(
		publicKey.PubKID,
		publicKey.PubKType,
	), b)
}

// GetPublicKey returns a publicKey from its index
func (k Keeper) GetPublicKey(
	ctx context.Context,
	pubKID string,
	pubKType string,

) (val types.PublicKey, found bool) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.PublicKeyKeyPrefix))

	b := store.Get(types.PublicKeyKey(
		pubKID,
		pubKType,
	))
	if b == nil {
		return val, false
	}

	k.cdc.MustUnmarshal(b, &val)
	return val, true
}

// RemovePublicKey removes a publicKey from the store
func (k Keeper) RemovePublicKey(
	ctx context.Context,
	pubKID string,
	pubKType string,

) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.PublicKeyKeyPrefix))
	store.Delete(types.PublicKeyKey(
		pubKID,
		pubKType,
	))
}

// GetAllPublicKey returns all publicKey
func (k Keeper) GetAllPublicKey(ctx context.Context) (list []types.PublicKey) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.PublicKeyKeyPrefix))
	iterator := storetypes.KVStorePrefixIterator(store, []byte{})

	defer iterator.Close()

	for ; iterator.Valid(); iterator.Next() {
		var val types.PublicKey
		k.cdc.MustUnmarshal(iterator.Value(), &val)
		list = append(list, val)
	}

	return
}
