package keeper

import (
	"context"

	"cosmossdk.io/store/prefix"
	storetypes "cosmossdk.io/store/types"
	"github.com/cosmos/cosmos-sdk/runtime"

	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

// The bank-send whitelist: accounts allowed to move coins directly, without the AML scan that every
// other account-to-account transfer goes through.
//
// Unlike most state in this module it is NOT forwarded to the enclave.  The enclave decides whether
// a scanned transfer is acceptable; whether a transfer is scanned AT ALL is a chain-level policy
// question, decided in the send restriction before the enclave is consulted.

// SetBankSendWhitelist adds or replaces one entry.
func (k Keeper) SetBankSendWhitelist(ctx context.Context, entry types.BankSendWhitelist) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.BankSendWhitelistKeyPrefix))
	b := k.cdc.MustMarshal(&entry)
	store.Set(types.BankSendWhitelistKey(entry.Address), b)
}

// GetBankSendWhitelist returns one entry, including its reason.
func (k Keeper) GetBankSendWhitelist(ctx context.Context, address string) (val types.BankSendWhitelist, found bool) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.BankSendWhitelistKeyPrefix))

	b := store.Get(types.BankSendWhitelistKey(address))
	if b == nil {
		return val, false
	}

	k.cdc.MustUnmarshal(b, &val)
	return val, true
}

// IsBankSendWhitelisted is the question the send restriction actually asks.  Separate from
// GetBankSendWhitelist so the hot path does not unmarshal a record it will not read.
func (k Keeper) IsBankSendWhitelisted(ctx context.Context, address string) bool {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.BankSendWhitelistKeyPrefix))
	return store.Has(types.BankSendWhitelistKey(address))
}

// RemoveBankSendWhitelist drops one entry.
func (k Keeper) RemoveBankSendWhitelist(ctx context.Context, address string) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.BankSendWhitelistKeyPrefix))
	store.Delete(types.BankSendWhitelistKey(address))
}

// GetAllBankSendWhitelist returns every entry, for genesis export and for querying.
func (k Keeper) GetAllBankSendWhitelist(ctx context.Context) (list []types.BankSendWhitelist) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.BankSendWhitelistKeyPrefix))
	iterator := storetypes.KVStorePrefixIterator(store, []byte{})

	defer iterator.Close()

	for ; iterator.Valid(); iterator.Next() {
		var val types.BankSendWhitelist
		k.cdc.MustUnmarshal(iterator.Value(), &val)
		list = append(list, val)
	}

	return
}
