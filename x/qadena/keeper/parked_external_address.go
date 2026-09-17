package keeper

import (
	"context"

	"cosmossdk.io/store/prefix"
	"github.com/cosmos/cosmos-sdk/runtime"

	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

// Parked pioneer addresses: the ExternalIPAddress a staking hook cleared from a pioneer's
// IntervalPublicKeyID row while its validator is out of the bonded set, held so re-bonding can
// restore it.  Written ONLY by keeper/staking_hooks.go.
//
// CHAIN-ONLY, like ScannedContractWhitelist and unlike most state in this module: plain store
// ops, NO EnclaveClient forward, NO AccumulateWrite, and the prefix is deliberately absent from
// mirroredStores (enclave_seed_page.go).  The enclave answers "is this pioneer a share-owner
// candidate" from the ROW's address being non-empty -- that is the entire mechanism -- so a
// mirrored copy of the parked value would be a second, contradictory answer to the same question.
// Absence from mirroredStores also keeps the prefix out of the seed pages and the chain/enclave
// divergence audit, both of which walk exactly that set; adding it there later without also
// teaching the enclave the prefix would fail every store-hash comparison (the PioneerJar
// membership lesson documented in enclave_seed_page.go).

// SetParkedExternalAddress adds or replaces one parked address.
func (k Keeper) SetParkedExternalAddress(ctx context.Context, entry types.ParkedExternalAddress) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.ParkedExternalAddressKeyPrefix))
	b := k.cdc.MustMarshal(&entry)
	store.Set(types.ParkedExternalAddressKey(entry.PubKID), b)
}

// GetParkedExternalAddress returns the parked address for one pioneer, by row PubKID.
func (k Keeper) GetParkedExternalAddress(ctx context.Context, pubKID string) (val types.ParkedExternalAddress, found bool) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.ParkedExternalAddressKeyPrefix))

	b := store.Get(types.ParkedExternalAddressKey(pubKID))
	if b == nil {
		return val, false
	}

	k.cdc.MustUnmarshal(b, &val)
	return val, true
}

// RemoveParkedExternalAddress drops one parked address, after a restore has consumed it.
func (k Keeper) RemoveParkedExternalAddress(ctx context.Context, pubKID string) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.ParkedExternalAddressKeyPrefix))
	store.Delete(types.ParkedExternalAddressKey(pubKID))
}

// GetAllParkedExternalAddress returns every parked address, for genesis export.
func (k Keeper) GetAllParkedExternalAddress(ctx context.Context) (list []types.ParkedExternalAddress) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.ParkedExternalAddressKeyPrefix))
	iterator := store.Iterator(nil, nil)

	defer iterator.Close()

	for ; iterator.Valid(); iterator.Next() {
		var val types.ParkedExternalAddress
		k.cdc.MustUnmarshal(iterator.Value(), &val)
		list = append(list, val)
	}

	return
}
