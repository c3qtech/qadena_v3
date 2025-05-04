package keeper

import (
	"context"

	"qadena/x/qadena/types"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (k Keeper) Incentives(goCtx context.Context, req *types.QueryIncentivesRequest) (*types.QueryIncentivesResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	ctx := sdk.UnwrapSDKContext(goCtx)

	moduleParams := k.GetParams(ctx)

	incentiveCoin := moduleParams.GetCreateWalletIncentive()
	ephemeralIncentiveCoin := moduleParams.GetCreateEphemeralWalletIncentive()
	transparentIncentiveCoin := moduleParams.GetCreateWalletTransparentIncentive()
	ephemeralTransparentIncentiveCoin := moduleParams.GetCreateEphemeralWalletTransparentIncentive()

	incentiveCoin = sdk.NormalizeCoin(incentiveCoin)
	ephemeralIncentiveCoin = sdk.NormalizeCoin(ephemeralIncentiveCoin)
	transparentIncentiveCoin = sdk.NormalizeCoin(transparentIncentiveCoin)
	ephemeralTransparentIncentiveCoin = sdk.NormalizeCoin(ephemeralTransparentIncentiveCoin)

	return &types.QueryIncentivesResponse{
		CreateWalletIncentive:                     incentiveCoin,
		CreateEphemeralWalletIncentive:            ephemeralIncentiveCoin,
		CreateWalletTransparentIncentive:          transparentIncentiveCoin,
		CreateEphemeralWalletTransparentIncentive: ephemeralTransparentIncentiveCoin,
	}, nil
}
