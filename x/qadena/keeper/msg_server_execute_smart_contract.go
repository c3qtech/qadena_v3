package keeper

import (
	"context"

	"github.com/c3qtech/qadena_v3/x/qadena/types"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

func (k msgServer) ExecuteSmartContract(goCtx context.Context, msg *types.MsgExecuteSmartContract) (*types.MsgExecuteSmartContractResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	// TODO: Handling the message
	_ = ctx

	return &types.MsgExecuteSmartContractResponse{}, nil
}
