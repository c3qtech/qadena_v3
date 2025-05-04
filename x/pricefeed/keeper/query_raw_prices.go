package keeper

import (
	"context"

	"qadena/x/pricefeed/types"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (k Keeper) RawPrices(goCtx context.Context, req *types.QueryRawPricesRequest) (*types.QueryRawPricesResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	ctx := sdk.UnwrapSDKContext(goCtx)

	_, found := k.GetMarket(ctx, req.MarketId)
	if !found {
		return nil, status.Error(codes.NotFound, "invalid market ID")
	}

	prices := k.GetRawPrices(ctx, req.MarketId)

	var pricesNew []*types.PostedPrice
	for i := 0; i < len(prices); i++ {
		pricesNew = append(pricesNew, &prices[i])
	}

	return &types.QueryRawPricesResponse{
		RawPrices: pricesNew,
	}, nil
}
