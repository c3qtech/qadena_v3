package keeper

import (
	"context"

	"qadena_v3/x/qadena/types"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"qadena_v3/x/qadena/common"
)

func (k Keeper) EnclaveSecretShare(goCtx context.Context, req *types.QueryEnclaveSecretShareRequest) (response *types.QueryEnclaveSecretShareResponse, err error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	ctx := sdk.UnwrapSDKContext(goCtx)

	err, response = k.EnclaveQuerySecretShare(ctx, req)

	if err != nil {
		common.ContextError(ctx, "EnclaveQueryRecoverKeyShare returned error "+err.Error())
	} else {
		common.ContextDebug(ctx, "EnclaveQueryRecoverKeyShare OK")
	}

	return
}
