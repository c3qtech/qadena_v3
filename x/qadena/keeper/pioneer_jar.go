package keeper

import (
	"context"

	"github.com/c3qtech/qadena_v3/x/qadena/types"

	"github.com/c3qtech/qadena_v3/x/qadena/common"

	"cosmossdk.io/store/prefix"
	storetypes "cosmossdk.io/store/types"
	"github.com/cosmos/cosmos-sdk/runtime"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// SetPioneerJar set a specific pioneerJar in the store from its index
func (k Keeper) SetPioneerJar(ctx context.Context, pioneerJar types.PioneerJar) {
	sdkctx := sdk.UnwrapSDKContext(ctx)
	err := k.EnclaveClientSetPioneerJar(sdkctx, pioneerJar) // forward this to the enclave
	if err != nil {
		common.ContextError(sdkctx, "EnclaveClientSetPioneerJar err "+err.Error())
		// throw an exception
		panic(err.Error())
	}

	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.PioneerJarKeyPrefix))
	b := k.cdc.MustMarshal(&pioneerJar)
	store.Set(types.PioneerJarKey(
		pioneerJar.PioneerID,
	), b)
}

// GetPioneerJar returns a pioneerJar from its index
func (k Keeper) GetPioneerJar(
	ctx context.Context,
	pioneerID string,

) (val types.PioneerJar, found bool) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.PioneerJarKeyPrefix))

	b := store.Get(types.PioneerJarKey(
		pioneerID,
	))
	if b == nil {
		return val, false
	}

	k.cdc.MustUnmarshal(b, &val)
	return val, true
}

// RemovePioneerJar removes a pioneerJar from the store
func (k Keeper) RemovePioneerJar(
	ctx context.Context,
	pioneerID string,

) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.PioneerJarKeyPrefix))
	store.Delete(types.PioneerJarKey(
		pioneerID,
	))
}

// GetAllPioneerJar returns all pioneerJar
func (k Keeper) GetAllPioneerJar(ctx context.Context) (list []types.PioneerJar) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.PioneerJarKeyPrefix))
	iterator := storetypes.KVStorePrefixIterator(store, []byte{})

	defer iterator.Close()

	for ; iterator.Valid(); iterator.Next() {
		var val types.PioneerJar
		k.cdc.MustUnmarshal(iterator.Value(), &val)
		list = append(list, val)
	}

	return
}
