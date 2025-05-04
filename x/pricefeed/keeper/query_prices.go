package keeper

import (
	"context"

	"qadena/x/pricefeed/types"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (k Keeper) Prices(goCtx context.Context, req *types.QueryPricesRequest) (*types.QueryPricesResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	ctx := sdk.UnwrapSDKContext(goCtx)

	currentPrices := k.GetCurrentPrices(ctx)

	var currentPricesNew []*types.CurrentPrice

	for i := 0; i < len(currentPrices); i++ {
		if currentPrices[i].MarketId != "" {
			currentPricesNew = append(currentPricesNew, &currentPrices[i])
		}
	}

	return &types.QueryPricesResponse{
		Prices: currentPricesNew,
	}, nil
}
