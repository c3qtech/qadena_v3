package keeper

import (
	"context"

	"github.com/c3qtech/qadena_v3/x/qadena/types"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// EnclavePrivateState serves this node's enclave-private tables at a height to an attested peer.
//
// The chain does no authorization of its own here, deliberately: the enclave verifies the caller's
// remote report against an ACTIVE on-chain EnclaveIdentity before reading a byte, and it is the
// only party that can, since the chain cannot see an SGX quote's measurement.  Anything this layer
// added would be advisory at best and misleading at worst.
func (k Keeper) EnclavePrivateState(goCtx context.Context, req *types.QueryEnclavePrivateStateRequest) (*types.QueryEnclavePrivateStateResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	ctx := sdk.UnwrapSDKContext(goCtx)

	err, res := k.EnclaveQueryPrivateState(ctx, req)

	return res, err
}

// EnclavePrivateStateAvailability reports which heights this node's enclave can serve.
//
// Unattested: it carries no secrets, and a peer that lies about its range costs the caller only a
// wasted attempt, because the transfer itself fails closed.
func (k Keeper) EnclavePrivateStateAvailability(goCtx context.Context, req *types.QueryEnclavePrivateStateAvailabilityRequest) (*types.QueryEnclavePrivateStateAvailabilityResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	ctx := sdk.UnwrapSDKContext(goCtx)

	err, res := k.EnclaveQueryPrivateStateAvailability(ctx, req)

	return res, err
}
