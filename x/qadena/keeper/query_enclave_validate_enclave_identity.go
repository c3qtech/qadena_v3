package keeper

import (
	"context"

	"github.com/c3qtech/qadena_v3/x/qadena/types"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (k Keeper) EnclaveValidateEnclaveIdentity(goCtx context.Context, req *types.QueryEnclaveValidateEnclaveIdentityRequest) (*types.QueryEnclaveValidateEnclaveIdentityResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	ctx := sdk.UnwrapSDKContext(goCtx)

	err, res := k.EnclaveQueryValidateEnclaveIdentity(ctx, req)

	return res, err
}
