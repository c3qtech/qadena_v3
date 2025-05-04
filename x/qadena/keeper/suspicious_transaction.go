package keeper

import (
	"context"
	"encoding/binary"

	"qadena_v3/x/qadena/types"

	"cosmossdk.io/store/prefix"
	storetypes "cosmossdk.io/store/types"
	"github.com/cosmos/cosmos-sdk/runtime"
)

// GetSuspiciousTransactionCount get the total number of suspiciousTransaction
func (k Keeper) GetSuspiciousTransactionCount(ctx context.Context) uint64 {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, []byte{})
	byteKey := types.KeyPrefix(types.SuspiciousTransactionCountKey)
	bz := store.Get(byteKey)

	// Count doesn't exist: no element
	if bz == nil {
		return 0
	}

	// Parse bytes
	return binary.BigEndian.Uint64(bz)
}

// SetSuspiciousTransactionCount set the total number of suspiciousTransaction
func (k Keeper) SetSuspiciousTransactionCount(ctx context.Context, count uint64) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, []byte{})
	byteKey := types.KeyPrefix(types.SuspiciousTransactionCountKey)
	bz := make([]byte, 8)
	binary.BigEndian.PutUint64(bz, count)
	store.Set(byteKey, bz)
}

// AppendSuspiciousTransaction appends a suspiciousTransaction in the store with a new id and update the count
func (k Keeper) AppendSuspiciousTransaction(
	ctx context.Context,
	suspiciousTransaction types.SuspiciousTransaction,
) uint64 {
	// Create the suspiciousTransaction
	count := k.GetSuspiciousTransactionCount(ctx)

	// Set the ID of the appended value
	suspiciousTransaction.Id = count

	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.SuspiciousTransactionKey))
	appendedValue := k.cdc.MustMarshal(&suspiciousTransaction)
	store.Set(GetSuspiciousTransactionIDBytes(suspiciousTransaction.Id), appendedValue)

	// Update suspiciousTransaction count
	k.SetSuspiciousTransactionCount(ctx, count+1)

	return count
}

// SetSuspiciousTransaction set a specific suspiciousTransaction in the store
func (k Keeper) SetSuspiciousTransaction(ctx context.Context, suspiciousTransaction types.SuspiciousTransaction) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.SuspiciousTransactionKey))
	b := k.cdc.MustMarshal(&suspiciousTransaction)
	store.Set(GetSuspiciousTransactionIDBytes(suspiciousTransaction.Id), b)
}

// GetSuspiciousTransaction returns a suspiciousTransaction from its id
func (k Keeper) GetSuspiciousTransaction(ctx context.Context, id uint64) (val types.SuspiciousTransaction, found bool) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.SuspiciousTransactionKey))
	b := store.Get(GetSuspiciousTransactionIDBytes(id))
	if b == nil {
		return val, false
	}
	k.cdc.MustUnmarshal(b, &val)
	return val, true
}

// RemoveSuspiciousTransaction removes a suspiciousTransaction from the store
func (k Keeper) RemoveSuspiciousTransaction(ctx context.Context, id uint64) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.SuspiciousTransactionKey))
	store.Delete(GetSuspiciousTransactionIDBytes(id))
}

// GetAllSuspiciousTransaction returns all suspiciousTransaction
func (k Keeper) GetAllSuspiciousTransaction(ctx context.Context) (list []types.SuspiciousTransaction) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.SuspiciousTransactionKey))
	iterator := storetypes.KVStorePrefixIterator(store, []byte{})

	defer iterator.Close()

	for ; iterator.Valid(); iterator.Next() {
		var val types.SuspiciousTransaction
		k.cdc.MustUnmarshal(iterator.Value(), &val)
		list = append(list, val)
	}

	return
}

// GetSuspiciousTransactionIDBytes returns the byte representation of the ID
func GetSuspiciousTransactionIDBytes(id uint64) []byte {
	bz := types.KeyPrefix(types.SuspiciousTransactionKey)
	bz = append(bz, []byte("/")...)
	bz = binary.BigEndian.AppendUint64(bz, id)
	return bz
}
