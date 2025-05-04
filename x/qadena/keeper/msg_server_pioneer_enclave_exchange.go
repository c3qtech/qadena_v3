package keeper

import (
	"context"

	"qadena/x/qadena/types"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

func (k msgServer) PioneerEnclaveExchange(goCtx context.Context, msg *types.MsgPioneerEnclaveExchange) (*types.MsgPioneerEnclaveExchangeResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	// TODO: Handling the message
	_ = ctx

	return &types.MsgPioneerEnclaveExchangeResponse{}, nil
}
