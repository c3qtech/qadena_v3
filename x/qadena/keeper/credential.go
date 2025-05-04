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

// SetCredential set a specific credential in the store from its index
func (k Keeper) SetCredential(ctx context.Context, credential types.Credential) error {
	sdkctx := sdk.UnwrapSDKContext(ctx)
	err := k.EnclaveClientSetCredential(sdkctx, credential) // forward this to the enclave
	if err != nil {
		common.ContextError(sdkctx, "EnclaveClientSetCredential err "+err.Error())
		return err
	}

	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.CredentialKeyPrefix))
	b := k.cdc.MustMarshal(&credential)
	store.Set(types.CredentialKey(
		credential.CredentialID,
		credential.CredentialType,
	), b)

	return nil
}

func (k Keeper) SetCredentialNoEnclave(ctx context.Context, credential types.Credential) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.CredentialKeyPrefix))
	b := k.cdc.MustMarshal(&credential)
	store.Set(types.CredentialKey(
		credential.CredentialID,
		credential.CredentialType,
	), b)
}

// GetCredential returns a credential from its index
func (k Keeper) GetCredential(
	ctx context.Context,
	credentialID string,
	credentialType string,

) (val types.Credential, found bool) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.CredentialKeyPrefix))

	b := store.Get(types.CredentialKey(
		credentialID,
		credentialType,
	))
	if b == nil {
		return val, false
	}

	k.cdc.MustUnmarshal(b, &val)
	return val, true
}

// RemoveCredential removes a credential from the store
func (k Keeper) RemoveCredential(
	ctx context.Context,
	credentialID string,
	credentialType string,

) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.CredentialKeyPrefix))
	store.Delete(types.CredentialKey(
		credentialID,
		credentialType,
	))
}

// GetAllCredential returns all credential
func (k Keeper) GetAllCredential(ctx context.Context) (list []types.Credential) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.CredentialKeyPrefix))
	iterator := storetypes.KVStorePrefixIterator(store, []byte{})

	defer iterator.Close()

	for ; iterator.Valid(); iterator.Next() {
		var val types.Credential
		k.cdc.MustUnmarshal(iterator.Value(), &val)
		list = append(list, val)
	}

	return
}
