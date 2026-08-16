package keeper

import (
	"context"

	"github.com/c3qtech/qadena_v3/x/qadena/types"

	"cosmossdk.io/store/prefix"
	storetypes "cosmossdk.io/store/types"
	"github.com/cosmos/cosmos-sdk/runtime"

	"github.com/c3qtech/qadena_v3/x/qadena/common"

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
	// Shadow accumulator, maintained BEFORE the write so an overwrite can subtract the
	// row's previous value.  The scan in StoreHashByKVStoreService stays authoritative.
	k.AccumulateWrite(ctx, types.CredentialKeyPrefix, types.CredentialKey(credential.CredentialID, credential.CredentialType), b)
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
	// Shadow accumulator, maintained BEFORE the write so an overwrite can subtract the
	// row's previous value.  The scan in StoreHashByKVStoreService stays authoritative.
	k.AccumulateWrite(ctx, types.CredentialKeyPrefix, types.CredentialKey(credential.CredentialID, credential.CredentialType), b)
	store.Set(types.CredentialKey(
		credential.CredentialID,
		credential.CredentialType,
	), b)
}

// RemoveCredentialNoEnclave deletes a credential from chain state without telling the enclave.
// It is the counterpart of SetCredentialNoEnclave and exists for the EndBlock sync, where the
// removal has already happened inside the enclave and is only being mirrored here.
func (k Keeper) RemoveCredentialNoEnclave(ctx context.Context, credentialID string, credentialType string) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.CredentialKeyPrefix))
	// Shadow accumulator, maintained BEFORE the write so an overwrite can subtract the
	// row's previous value.  The scan in StoreHashByKVStoreService stays authoritative.
	k.AccumulateWrite(ctx, types.CredentialKeyPrefix, types.CredentialKey(credentialID, credentialType), nil)
	store.Delete(types.CredentialKey(
		credentialID,
		credentialType,
	))
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
// KeeperRemoveCredential removes a credential from the enclave first and then from chain state.
// requesterWalletID is empty when an identity provider is removing an ownerless credential, and
// the owner's walletID when a user is removing one of their own.
func (k Keeper) KeeperRemoveCredential(
	ctx context.Context,
	credentialID string,
	credentialType string,
	requesterWalletID string,
) error {
	sdkctx := sdk.UnwrapSDKContext(ctx)
	credential := types.Credential{
		CredentialID:   credentialID,
		CredentialType: credentialType,
	}
	err := k.EnclaveClientRemoveCredential(sdkctx, credential, requesterWalletID) // forward this to the enclave
	if err != nil {
		common.ContextError(sdkctx, "EnclaveClientRemoveCredential err "+err.Error())
		return err
	}
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.CredentialKeyPrefix))
	// Shadow accumulator, maintained BEFORE the write so an overwrite can subtract the
	// row's previous value.  The scan in StoreHashByKVStoreService stays authoritative.
	k.AccumulateWrite(ctx, types.CredentialKeyPrefix, types.CredentialKey(credentialID, credentialType), nil)
	store.Delete(types.CredentialKey(
		credentialID,
		credentialType,
	))
	return nil
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
