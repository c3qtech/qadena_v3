package keeper

import (
	"context"

	"qadena/x/dsvs/types"

	"cosmossdk.io/store/prefix"
	storetypes "cosmossdk.io/store/types"
	"github.com/cosmos/cosmos-sdk/runtime"
)

// SetDocumentHash set a specific documentHash in the store from its index
func (k Keeper) SetDocumentHash(ctx context.Context, documentHash types.DocumentHash) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.DocumentHashKeyPrefix))
	b := k.cdc.MustMarshal(&documentHash)
	store.Set(documentHash.Hash, b)
}

// GetDocumentHash returns a documentHash from its index
func (k Keeper) GetDocumentHash(
	ctx context.Context,
	hash []byte,

) (val types.DocumentHash, found bool) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.DocumentHashKeyPrefix))

	b := store.Get(hash)
	if b == nil {
		return val, false
	}

	k.cdc.MustUnmarshal(b, &val)
	return val, true
}

// RemoveDocumentHash removes a documentHash from the store
func (k Keeper) RemoveDocumentHash(
	ctx context.Context,
	hash []byte,

) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.DocumentHashKeyPrefix))
	store.Delete(hash)
}

// GetAllDocumentHash returns all documentHash
func (k Keeper) GetAllDocumentHash(ctx context.Context) (list []types.DocumentHash) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.DocumentHashKeyPrefix))
	iterator := storetypes.KVStorePrefixIterator(store, []byte{})

	defer iterator.Close()

	for ; iterator.Valid(); iterator.Next() {
		var val types.DocumentHash
		k.cdc.MustUnmarshal(iterator.Value(), &val)
		list = append(list, val)
	}

	return
}
