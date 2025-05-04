package keeper

import (
	"context"

	"qadena/x/qadena/types"

	c "qadena/x/qadena/common"

	"cosmossdk.io/store/prefix"
	storetypes "cosmossdk.io/store/types"
	"github.com/cosmos/cosmos-sdk/runtime"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// SetEnclaveIdentity set a specific enclaveIdentity in the store from its index
func (k Keeper) SetEnclaveIdentity(ctx context.Context, enclaveIdentity types.EnclaveIdentity) {
	sdkctx := sdk.UnwrapSDKContext(ctx)

	err := k.EnclaveClientSetEnclaveIdentity(sdkctx, enclaveIdentity) // forward this to the enclave
	if err != nil {
		c.ContextError(sdkctx, "EnclaveClientSetEnclaveIdentity err "+err.Error())
		panic(err.Error())
	}

	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.EnclaveIdentityKeyPrefix))
	b := k.cdc.MustMarshal(&enclaveIdentity)
	store.Set(types.EnclaveIdentityKey(
		enclaveIdentity.UniqueID,
	), b)
}

// SetEnclaveIdentityNoEnclave set a specific enclaveIdentity in the store from its index
func (k Keeper) SetEnclaveIdentityNoEnclave(ctx context.Context, enclaveIdentity types.EnclaveIdentity) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.EnclaveIdentityKeyPrefix))
	b := k.cdc.MustMarshal(&enclaveIdentity)
	store.Set(types.EnclaveIdentityKey(
		enclaveIdentity.UniqueID,
	), b)
}

// GetEnclaveIdentity returns a enclaveIdentity from its index
func (k Keeper) GetEnclaveIdentity(
	ctx context.Context,
	uniqueID string,

) (val types.EnclaveIdentity, found bool) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.EnclaveIdentityKeyPrefix))

	b := store.Get(types.EnclaveIdentityKey(
		uniqueID,
	))
	if b == nil {
		return val, false
	}

	k.cdc.MustUnmarshal(b, &val)
	return val, true
}

// RemoveEnclaveIdentity removes a enclaveIdentity from the store
func (k Keeper) RemoveEnclaveIdentity(
	ctx context.Context,
	uniqueID string,

) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.EnclaveIdentityKeyPrefix))
	store.Delete(types.EnclaveIdentityKey(
		uniqueID,
	))
}

// GetAllEnclaveIdentity returns all enclaveIdentity
func (k Keeper) GetAllEnclaveIdentity(ctx context.Context) (list []types.EnclaveIdentity) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.EnclaveIdentityKeyPrefix))
	iterator := storetypes.KVStorePrefixIterator(store, []byte{})

	defer iterator.Close()

	for ; iterator.Valid(); iterator.Next() {
		var val types.EnclaveIdentity
		k.cdc.MustUnmarshal(iterator.Value(), &val)
		list = append(list, val)
	}

	return
}
