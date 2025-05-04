package keeper

import (
	"context"

	"qadena_v3/x/qadena/types"

	"qadena_v3/x/qadena/common"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (k Keeper) EnclaveRecoverKeyShare(goCtx context.Context, req *types.QueryEnclaveRecoverKeyShareRequest) (response *types.QueryEnclaveRecoverKeyShareResponse, err error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	ctx := sdk.UnwrapSDKContext(goCtx)

	err, response = k.EnclaveQueryRecoverKeyShare(ctx, req)

	if err != nil {
		common.ContextError(ctx, "EnclaveQueryRecoverKeyShare returned error "+err.Error())
	} else {
		common.ContextDebug(ctx, "EnclaveQueryRecoverKeyShare OK")
	}

	return
}
