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

// SetIntervalPublicKeyID set a specific intervalPublicKeyID in the store from its index
func (k Keeper) SetIntervalPublicKeyID(ctx context.Context, intervalPublicKeyID types.IntervalPublicKeyID) {
	sdkctx := sdk.UnwrapSDKContext(ctx)

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

		// Remember the key we are replacing, so a transaction built moments before a rotation is
		// still accepted after it -- see Keeper.GetIntervalPublicKeyWithPrevious.  Derived HERE
		// and nowhere else: every validator computes it from its own store, so no caller can
		// nominate a key of its choosing and no two nodes can disagree about what the previous key
		// was.
		if currentIntervalPublicKeyID.PubKID != intervalPublicKeyID.PubKID {
			intervalPublicKeyID.PreviousPubKID = currentIntervalPublicKeyID.PubKID
		} else {
			// The same key rewritten is not a rotation -- DeactivateServiceProvider does this to
			// change only the service provider type.  Carry the existing pointer rather than
			// pointing the record at itself, which would make a record its own predecessor and
			// silently widen the grace to a key that is still current.
			intervalPublicKeyID.PreviousPubKID = currentIntervalPublicKeyID.PreviousPubKID
		}

		// remove the old one by PubKID, so we don't keep growing the kvstore
		store.Delete(types.IntervalPublicKeyIDByPubKIDKey(
			currentIntervalPublicKeyID.PubKID,
		))
	} else {
		// First write for this (nodeID, nodeType).  Whatever PreviousPubKID arrived is kept:
		// InitGenesis is the only caller that can legitimately supply one, and preserving it is
		// what makes ExportGenesis -> InitGenesis a fixed point.  Dropping it here would silently
		// void the grace period for one interval on every chain restarted from an exported genesis.
		//
		// make sure we don't have a duplicate one stored by PubKID
		current = storeByPubKID.Get(types.IntervalPublicKeyIDByPubKIDKey(
			intervalPublicKeyID.PubKID,
		))
		if current != nil {
			common.ContextError(sdkctx, "SetIntervalPublicKeyID err, duplicate PubKID")
			panic("SetIntervalPublicKeyID err, duplicate PubKID")
		}

	}

	// Forwarded only once PreviousPubKID has been filled in, so the enclave stores byte-identical
	// content to the chain.  The IntervalPublicKeyID prefix is compared by GetStoreHash, so a
	// mismatch here would show up as a permanently out-of-sync store.  Still before either
	// store.Set, so a failed enclave call panics without leaving a half-applied write.
	err := k.EnclaveClientSetIntervalPublicKeyId(sdkctx, intervalPublicKeyID) // forward this to the enclave
	if err != nil {
		common.ContextError(sdkctx, "EnclaveClientIntervalPublicKeyId err "+err.Error())
		// throw an exception
		panic(err.Error())
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
