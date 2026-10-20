package keeper

import (
	"context"

	"cosmossdk.io/store/prefix"
	"github.com/cosmos/cosmos-sdk/runtime"
	sdk "github.com/cosmos/cosmos-sdk/types"

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

// PioneerHasDeparted reports whether a pioneer has been out of the bonded set long enough that it
// may be dropped from the owner set of SS interval keys it already holds.
//
// THIS IS THE ONLY DEFINITION OF "DEPARTED", and every caller must use it rather than testing
// parkedness directly: dropping an owner is a consensus action, so the answer has to be derived
// from chain state the same way on every node, at the same height.  Parked-ness alone is NOT that
// answer -- parking fires on any bonded->unbonding transition, including a downtime jail that
// resolves in minutes, and a pioneer that returns still physically holds its shares.
//
// Three ways this says "no", each deliberate:
//
//	grace == 0        the feature is OFF.  Params written before field 30 unmarshal zero, and so
//	                  does an empty param store, so an existing chain keeps today's behaviour
//	                  until governance sets the field.  Reading 0 as "drop immediately" would
//	                  change owner sets on upgrade, at a height replay cannot account for.
//	not parked        bonded, or never parked.  The ordinary case.
//	ParkedHeight == 0 parked before the field existed.  Treated as not-yet-departed rather than
//	                  "parked at genesis": the latter would make every pre-existing parked
//	                  pioneer instantly departed the moment this ships, which is exactly the
//	                  silent mass re-share this grace period exists to prevent.  Such an entry
//	                  gets a real height the next time its validator unbonds.
func (k Keeper) PioneerHasDeparted(ctx context.Context, pubKID string) bool {
	grace := k.GetParams(ctx).SsDepartureGrace
	if grace == 0 {
		return false
	}
	parked, found := k.GetParkedExternalAddress(ctx, pubKID)
	if !found || parked.ParkedHeight == 0 {
		return false
	}
	return sdk.UnwrapSDKContext(ctx).BlockHeight()-parked.ParkedHeight >= int64(grace)
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
