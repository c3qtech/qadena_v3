package keeper

import (
	"context"

	"qadena/x/pricefeed/types"

	"cosmossdk.io/store/prefix"
	"github.com/cosmos/cosmos-sdk/runtime"
	"github.com/cosmos/cosmos-sdk/types/query"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (k Keeper) PostedPriceAll(ctx context.Context, req *types.QueryAllPostedPriceRequest) (*types.QueryAllPostedPriceResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	var postedPrices []types.PostedPrice

	store := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	postedPriceStore := prefix.NewStore(store, types.KeyPrefix(types.PostedPriceKeyPrefix))

	pageRes, err := query.Paginate(postedPriceStore, req.Pagination, func(key []byte, value []byte) error {
		var postedPrice types.PostedPrice
		if err := k.cdc.Unmarshal(value, &postedPrice); err != nil {
			return err
		}

		postedPrices = append(postedPrices, postedPrice)
		return nil
	})

	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &types.QueryAllPostedPriceResponse{PostedPrice: postedPrices, Pagination: pageRes}, nil
}

func (k Keeper) PostedPrice(ctx context.Context, req *types.QueryGetPostedPriceRequest) (*types.QueryGetPostedPriceResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	val, found := k.GetPostedPrice(
		ctx,
		req.MarketId,
		req.OracleAddress,
	)
	if !found {
		return nil, status.Error(codes.NotFound, "not found")
	}

	return &types.QueryGetPostedPriceResponse{PostedPrice: val}, nil
}
