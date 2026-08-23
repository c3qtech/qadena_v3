package keeper

import (
	"context"

	"github.com/c3qtech/qadena_v3/x/qadena/types"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/c3qtech/qadena_v3/x/qadena/common"
)

// EnclaveSecretSharePrivK is the chain-side face of the who-has fallback: it forwards the query to
// this node's enclave, which serves a CACHED interval private key -- encrypted to the requesting
// enclave -- if and only if the requester's report verifies against the local trusted set.  All
// policy lives in the enclave; this is a pipe, exactly like EnclaveSecretShare.
func (k Keeper) EnclaveSecretSharePrivK(goCtx context.Context, req *types.QueryEnclaveSecretSharePrivKRequest) (response *types.QueryEnclaveSecretSharePrivKResponse, err error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	ctx := sdk.UnwrapSDKContext(goCtx)

	err, response = k.EnclaveQuerySecretSharePrivK(ctx, req)

	if err != nil {
		common.ContextError(ctx, "EnclaveQuerySecretSharePrivK returned error "+err.Error())
	} else {
		common.ContextDebug(ctx, "EnclaveQuerySecretSharePrivK OK")
	}

	return
}
