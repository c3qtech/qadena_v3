package keeper

import (
	"context"

	"github.com/c3qtech/qadena_v3/x/qadena/types"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// EnclaveMeasurement reports which enclave build this node runs, and whether that enclave holds a
// trusted set (i.e. whether it can bootstrap a joiner).
//
// Exists so add_full_node.sh can check, BEFORE minting a key or funding anything, that the joiner
// and the seed run the same measurement -- a joiner can only bootstrap trust from a seed running its
// own build, so a mismatch means sync-enclave will refuse.  Without this the operator discovers it
// from a rejected handshake several minutes into a join, in a message that names neither build.
func (k Keeper) EnclaveMeasurement(goCtx context.Context, req *types.QueryEnclaveMeasurementRequest) (*types.QueryEnclaveMeasurementResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	ctx := sdk.UnwrapSDKContext(goCtx)

	err, res := k.EnclaveQueryMeasurement(ctx, req)

	return res, err
}
