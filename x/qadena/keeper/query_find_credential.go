package keeper

import (
	"context"

	"qadena/x/qadena/types"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (k Keeper) FindCredential(goCtx context.Context, req *types.QueryFindCredentialRequest) (*types.QueryFindCredentialResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	ctx := sdk.UnwrapSDKContext(goCtx)

	err, val := k.EnclaveQueryFindCredential(ctx,
		req,
	)
	if err != nil {
		return nil, err
	}

	return val, nil
}
