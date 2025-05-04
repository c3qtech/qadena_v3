package keeper

import (
	"context"

	"qadena_v3/x/pricefeed/types"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (k Keeper) Markets(goCtx context.Context, req *types.QueryMarketsRequest) (*types.QueryMarketsResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	ctx := sdk.UnwrapSDKContext(goCtx)

	markets := k.GetMarkets(ctx)

	// convert to types.Markets*[]
	var marketsNew []*types.Market
	for i := 0; i < len(markets); i++ {
		marketsNew = append(marketsNew, &markets[i])
	}

	return &types.QueryMarketsResponse{
		Markets: marketsNew,
	}, nil
}
