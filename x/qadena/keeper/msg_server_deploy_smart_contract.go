package keeper

import (
	"context"

	"github.com/c3qtech/qadena_v3/x/qadena/types"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

func (k msgServer) DeploySmartContract(goCtx context.Context, msg *types.MsgDeploySmartContract) (*types.MsgDeploySmartContractResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	// TODO: Handling the message
	_ = ctx

	return &types.MsgDeploySmartContractResponse{}, nil
}
