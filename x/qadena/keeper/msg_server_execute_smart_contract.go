package keeper

import (
	"context"

	"qadena/x/qadena/types"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

func (k msgServer) ExecuteSmartContract(goCtx context.Context, msg *types.MsgExecuteSmartContract) (*types.MsgExecuteSmartContractResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	// TODO: Handling the message
	_ = ctx

	return &types.MsgExecuteSmartContractResponse{}, nil
}
