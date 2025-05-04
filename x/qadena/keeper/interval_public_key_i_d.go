package keeper

import (
	"context"

	"qadena_v3/x/qadena/types"

	"cosmossdk.io/store/prefix"
	storetypes "cosmossdk.io/store/types"
	"github.com/cosmos/cosmos-sdk/runtime"

	"qadena_v3/x/qadena/common"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// SetIntervalPublicKeyID set a specific intervalPublicKeyID in the store from its index
func (k Keeper) SetIntervalPublicKeyID(ctx context.Context, intervalPublicKeyID types.IntervalPublicKeyID) {
	sdkctx := sdk.UnwrapSDKContext(ctx)
	err := k.EnclaveClientSetIntervalPublicKeyId(sdkctx, intervalPublicKeyID) // forward this to the enclave
	if err != nil {
		common.ContextError(sdkctx, "EnclaveClientIntervalPublicKeyId err "+err.Error())
		// throw an exception
		panic(err.Error())
	}

	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.IntervalPublicKeyIDKeyPrefix))
	storeByPubKID := prefix.NewStore(storeAdapter, types.KeyPrefix(types.IntervalPublicKeyIDByPubKIDKeyPrefix))

	current := store.Get(types.IntervalPublicKeyIDKey(
		intervalPublicKeyID.NodeID,
		intervalPublicKeyID.NodeType,
	))
	if current != nil {
		var currentIntervalPublicKeyID types.IntervalPublicKeyID
		k.cdc.MustUnmarshal(current, &currentIntervalPublicKeyID)
		// remove the old one by PubKID, so we don't keep growing the kvstore
		store.Delete(types.IntervalPublicKeyIDByPubKIDKey(
			currentIntervalPublicKeyID.PubKID,
		))
	} else {
		// make sure we don't have a duplicate one stored by PubKID
		current = storeByPubKID.Get(types.IntervalPublicKeyIDByPubKIDKey(
			intervalPublicKeyID.PubKID,
		))
		if current != nil {
			common.ContextError(sdkctx, "SetIntervalPublicKeyID err, duplicate PubKID")
			panic("SetIntervalPublicKeyID err, duplicate PubKID")
		}

	}

	b := k.cdc.MustMarshal(&intervalPublicKeyID)
	store.Set(types.IntervalPublicKeyIDKey(
		intervalPublicKeyID.NodeID,
		intervalPublicKeyID.NodeType,
	), b)

	// stores an alternate way of finding this IntervalPublicKeyID
	storeByPubKID.Set(types.IntervalPublicKeyIDByPubKIDKey(
		intervalPublicKeyID.PubKID,
	), b)

}

// GetIntervalPublicKeyID returns a intervalPublicKeyID from its index
func (k Keeper) GetIntervalPublicKeyID(
	ctx context.Context,
	nodeID string,
	nodeType string,

) (val types.IntervalPublicKeyID, found bool) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.IntervalPublicKeyIDKeyPrefix))

	b := store.Get(types.IntervalPublicKeyIDKey(
		nodeID,
		nodeType,
	))
	if b == nil {
		return val, false
	}

	k.cdc.MustUnmarshal(b, &val)
	return val, true
}

// GetIntervalPublicKeyIDByPubKID returns a intervalPublicKeyID from its index
func (k Keeper) GetIntervalPublicKeyIDByPubKID(
	ctx context.Context,
	pubKID string,
) (val types.IntervalPublicKeyID, found bool) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.IntervalPublicKeyIDByPubKIDKeyPrefix))

	b := store.Get(types.IntervalPublicKeyIDByPubKIDKey(
		pubKID,
	))
	if b == nil {
		return val, false
	}

	k.cdc.MustUnmarshal(b, &val)
	return val, true
}

// RemoveIntervalPublicKeyID removes a intervalPublicKeyID from the store
func (k Keeper) RemoveIntervalPublicKeyID(
	ctx context.Context,
	nodeID string,
	nodeType string,

) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.IntervalPublicKeyIDKeyPrefix))
	store.Delete(types.IntervalPublicKeyIDKey(
		nodeID,
		nodeType,
	))
}

// GetAllIntervalPublicKeyID returns all intervalPublicKeyID
func (k Keeper) GetAllIntervalPublicKeyID(ctx context.Context) (list []types.IntervalPublicKeyID) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.IntervalPublicKeyIDKeyPrefix))
	iterator := storetypes.KVStorePrefixIterator(store, []byte{})

	defer iterator.Close()

	for ; iterator.Valid(); iterator.Next() {
		var val types.IntervalPublicKeyID
		k.cdc.MustUnmarshal(iterator.Value(), &val)
		list = append(list, val)
	}

	return
}
