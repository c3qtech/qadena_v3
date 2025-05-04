package keeper

import (
	"context"

	"qadena_v3/x/qadena/types"

	c "qadena_v3/x/qadena/common"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (k Keeper) Treasury(goCtx context.Context, req *types.QueryTreasuryRequest) (*types.QueryTreasuryResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	ctx := sdk.UnwrapSDKContext(goCtx)

	treasuryAddress := k.getTreasuryAddress(ctx)
	c.ContextDebug(ctx, "treasuryAddress "+treasuryAddress.String())

	total := k.bankKeeper.GetBalance(ctx, treasuryAddress, types.AQadenaTokenDenom)
	qadenaModuleAddr := k.accountKeeper.GetModuleAddress(types.ModuleName)
	encrypted := k.bankKeeper.GetBalance(ctx, qadenaModuleAddr, types.AQadenaTokenDenom)

	return &types.QueryTreasuryResponse{TotalBalance: total, EncryptedBalance: encrypted}, nil
}
