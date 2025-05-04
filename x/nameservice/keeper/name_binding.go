package keeper

import (
	"context"

	"github.com/c3qtech/qadena_v3/x/nameservice/types"

	"cosmossdk.io/store/prefix"
	storetypes "cosmossdk.io/store/types"
	"github.com/cosmos/cosmos-sdk/runtime"
)

// SetNameBinding set a specific nameBinding in the store from its index
func (k Keeper) SetNameBinding(ctx context.Context, nameBinding types.NameBinding) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.NameBindingKeyPrefix))
	b := k.cdc.MustMarshal(&nameBinding)
	store.Set(types.NameBindingKey(
		nameBinding.Credential,
		nameBinding.CredentialType,
	), b)
}

// GetNameBinding returns a nameBinding from its index
func (k Keeper) GetNameBinding(
	ctx context.Context,
	credential string,
	credentialType string,

) (val types.NameBinding, found bool) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.NameBindingKeyPrefix))

	b := store.Get(types.NameBindingKey(
		credential,
		credentialType,
	))
	if b == nil {
		return val, false
	}

	k.cdc.MustUnmarshal(b, &val)
	return val, true
}

// RemoveNameBinding removes a nameBinding from the store
func (k Keeper) RemoveNameBinding(
	ctx context.Context,
	credential string,
	credentialType string,

) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.NameBindingKeyPrefix))
	store.Delete(types.NameBindingKey(
		credential,
		credentialType,
	))
}

// GetAllNameBinding returns all nameBinding
func (k Keeper) GetAllNameBinding(ctx context.Context) (list []types.NameBinding) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.NameBindingKeyPrefix))
	iterator := storetypes.KVStorePrefixIterator(store, []byte{})

	defer iterator.Close()

	for ; iterator.Valid(); iterator.Next() {
		var val types.NameBinding
		k.cdc.MustUnmarshal(iterator.Value(), &val)
		list = append(list, val)
	}

	return
}
