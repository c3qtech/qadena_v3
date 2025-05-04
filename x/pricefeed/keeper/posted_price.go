package keeper

import (
	"context"

	"github.com/c3qtech/qadena_v3/x/pricefeed/types"

	"cosmossdk.io/store/prefix"
	storetypes "cosmossdk.io/store/types"
	"github.com/cosmos/cosmos-sdk/runtime"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// SetPostedPrice set a specific postedPrice in the store from its index
func (k Keeper) SetPostedPrice(ctx context.Context, postedPrice types.PostedPrice) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.PostedPriceKeyPrefix))
	b := k.cdc.MustMarshal(&postedPrice)
	store.Set(types.PostedPriceKey(
		postedPrice.MarketId,
		postedPrice.OracleAddress,
	), b)
}

// GetPostedPrice returns a postedPrice from its index
func (k Keeper) GetPostedPrice(
	ctx context.Context,
	marketId string,
	oracleAddress sdk.AccAddress,

) (val types.PostedPrice, found bool) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.PostedPriceKeyPrefix))

	b := store.Get(types.PostedPriceKey(
		marketId,
		oracleAddress,
	))
	if b == nil {
		return val, false
	}

	k.cdc.MustUnmarshal(b, &val)
	return val, true
}

// RemovePostedPrice removes a postedPrice from the store
func (k Keeper) RemovePostedPrice(
	ctx context.Context,
	marketId string,
	oracleAddress sdk.AccAddress,

) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.PostedPriceKeyPrefix))
	store.Delete(types.PostedPriceKey(
		marketId,
		oracleAddress,
	))
}

// GetAllPostedPrice returns all postedPrice
func (k Keeper) GetAllPostedPrice(ctx context.Context) (list []types.PostedPrice) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.PostedPriceKeyPrefix))
	iterator := storetypes.KVStorePrefixIterator(store, []byte{})

	defer iterator.Close()

	for ; iterator.Valid(); iterator.Next() {
		var val types.PostedPrice
		k.cdc.MustUnmarshal(iterator.Value(), &val)
		list = append(list, val)
	}

	return
}
