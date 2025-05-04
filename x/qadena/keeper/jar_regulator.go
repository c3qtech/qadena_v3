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

// SetJarRegulator set a specific jarRegulator in the store from its index
func (k Keeper) SetJarRegulator(ctx context.Context, jarRegulator types.JarRegulator) {
	sdkctx := sdk.UnwrapSDKContext(ctx)
	err := k.EnclaveClientSetJarRegulator(sdkctx, jarRegulator) // forward this to the enclave
	if err != nil {
		common.ContextDebug(sdkctx, "EnclaveClientSetJarRegulator err "+err.Error())
		panic(err.Error())
	}

	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.JarRegulatorKeyPrefix))
	b := k.cdc.MustMarshal(&jarRegulator)
	store.Set(types.JarRegulatorKey(
		jarRegulator.JarID,
	), b)
}

// GetJarRegulator returns a jarRegulator from its index
func (k Keeper) GetJarRegulator(
	ctx context.Context,
	jarID string,

) (val types.JarRegulator, found bool) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.JarRegulatorKeyPrefix))

	b := store.Get(types.JarRegulatorKey(
		jarID,
	))
	if b == nil {
		return val, false
	}

	k.cdc.MustUnmarshal(b, &val)
	return val, true
}

// RemoveJarRegulator removes a jarRegulator from the store
func (k Keeper) RemoveJarRegulator(
	ctx context.Context,
	jarID string,

) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.JarRegulatorKeyPrefix))
	store.Delete(types.JarRegulatorKey(
		jarID,
	))
}

// GetAllJarRegulator returns all jarRegulator
func (k Keeper) GetAllJarRegulator(ctx context.Context) (list []types.JarRegulator) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.JarRegulatorKeyPrefix))
	iterator := storetypes.KVStorePrefixIterator(store, []byte{})

	defer iterator.Close()

	for ; iterator.Valid(); iterator.Next() {
		var val types.JarRegulator
		k.cdc.MustUnmarshal(iterator.Value(), &val)
		list = append(list, val)
	}

	return
}
