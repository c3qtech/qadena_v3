package keeper

import (
	"context"

	"github.com/c3qtech/qadena_v3/x/qadena/types"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Treasury keeps its proto/RPC name deliberately: renaming it is a breaking API change to the
// query surface and to any client, which is a separate decision from the state-key rename.
// What it returns is the INCENTIVE POOL balance -- the account create_wallet incentives are paid from.
func (k Keeper) Treasury(goCtx context.Context, req *types.QueryTreasuryRequest) (*types.QueryTreasuryResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	ctx := sdk.UnwrapSDKContext(goCtx)

	incentivePoolAddress := k.getIncentivePoolAddress(ctx)
	c.ContextDebug(ctx, "incentivePoolAddress "+incentivePoolAddress.String())

	total := k.bankKeeper.GetBalance(ctx, incentivePoolAddress, types.AQadenaTokenDenom)
	qadenaModuleAddr := k.accountKeeper.GetModuleAddress(types.ModuleName)
	encrypted := k.bankKeeper.GetBalance(ctx, qadenaModuleAddr, types.AQadenaTokenDenom)

	return &types.QueryTreasuryResponse{TotalBalance: total, EncryptedBalance: encrypted}, nil
}
