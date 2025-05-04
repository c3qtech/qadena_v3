package keeper

import (
	"context"

	"qadena/x/qadena/types"

	"cosmossdk.io/store/prefix"
	storetypes "cosmossdk.io/store/types"
	"github.com/cosmos/cosmos-sdk/runtime"

	c "qadena/x/qadena/common"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// SetWallet set a specific wallet in the store from its index
func (k Keeper) SetWallet(ctx context.Context, wallet types.Wallet) {
	sdkctx := sdk.UnwrapSDKContext(ctx)

	err := k.EnclaveClientSetWallet(sdkctx, wallet) // forward this to the enclave
	if err != nil {
		c.ContextError(sdkctx, "EnclaveClientSetWallet err "+err.Error())
		panic(err.Error())
	}

	var sw types.StableWallet
	c.SetStableWallet(wallet, &sw)

	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.WalletKeyPrefix))
	b := k.cdc.MustMarshal(&sw)
	store.Set(types.WalletKey(
		wallet.WalletID,
	), b)
}

// SetWallet set a specific wallet in the store from its index
func (k Keeper) SetWalletNoEnclave(ctx context.Context, wallet types.Wallet) {
	var sw types.StableWallet
	c.SetStableWallet(wallet, &sw)

	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.WalletKeyPrefix))
	b := k.cdc.MustMarshal(&sw)
	store.Set(types.WalletKey(
		wallet.WalletID,
	), b)
}

// GetWallet returns a wallet from its index
func (k Keeper) GetWallet(
	ctx context.Context,
	walletID string,

) (val types.Wallet, found bool) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.WalletKeyPrefix))

	b := store.Get(types.WalletKey(
		walletID,
	))
	if b == nil {
		return val, false
	}

	k.cdc.MustUnmarshal(b, &val)
	return val, true
}

// RemoveWallet removes a wallet from the store
func (k Keeper) RemoveWallet(
	ctx context.Context,
	walletID string,

) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.WalletKeyPrefix))
	store.Delete(types.WalletKey(
		walletID,
	))
}

// GetAllWallet returns all wallet
func (k Keeper) GetAllWallet(ctx context.Context) (list []types.Wallet) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.WalletKeyPrefix))
	iterator := storetypes.KVStorePrefixIterator(store, []byte{})

	defer iterator.Close()

	for ; iterator.Valid(); iterator.Next() {
		var val types.Wallet
		k.cdc.MustUnmarshal(iterator.Value(), &val)
		list = append(list, val)
	}

	return
}
