package keeper

import (
	"context"

	"github.com/c3qtech/qadena_v3/x/qadena/types"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (k Keeper) EnclaveSyncEnclave(goCtx context.Context, req *types.QueryEnclaveSyncEnclaveRequest) (*types.QueryEnclaveSyncEnclaveResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	ctx := sdk.UnwrapSDKContext(goCtx)

	err, res := k.EnclaveQuerySyncEnclave(ctx, req)

	return res, err
}
