package keeper

import (
	"context"

	"github.com/c3qtech/qadena_v3/x/dsvs/types"

	"cosmossdk.io/store/prefix"
	storetypes "cosmossdk.io/store/types"
	"github.com/cosmos/cosmos-sdk/runtime"
)

// SetDocument set a specific document in the store from its index
func (k Keeper) SetDocument(ctx context.Context, document types.Document) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.DocumentKeyPrefix))
	b := k.cdc.MustMarshal(&document)
	store.Set(types.DocumentKey(
		document.DocumentID,
	), b)
}

// GetDocument returns a document from its index
func (k Keeper) GetDocument(
	ctx context.Context,
	documentID string,

) (val types.Document, found bool) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.DocumentKeyPrefix))

	b := store.Get(types.DocumentKey(
		documentID,
	))
	if b == nil {
		return val, false
	}

	k.cdc.MustUnmarshal(b, &val)
	return val, true
}

// RemoveDocument removes a document from the store
func (k Keeper) RemoveDocument(
	ctx context.Context,
	documentID string,

) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.DocumentKeyPrefix))
	store.Delete(types.DocumentKey(
		documentID,
	))
}

// GetAllDocument returns all document
func (k Keeper) GetAllDocument(ctx context.Context) (list []types.Document) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.DocumentKeyPrefix))
	iterator := storetypes.KVStorePrefixIterator(store, []byte{})

	defer iterator.Close()

	for ; iterator.Valid(); iterator.Next() {
		var val types.Document
		k.cdc.MustUnmarshal(iterator.Value(), &val)
		list = append(list, val)
	}

	return
}
