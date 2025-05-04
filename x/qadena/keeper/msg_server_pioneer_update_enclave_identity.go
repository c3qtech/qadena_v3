package keeper

import (
	"context"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"qadena_v3/x/qadena/common"

	"qadena_v3/x/qadena/types"
)

func (k msgServer) PioneerUpdateEnclaveIdentity(goCtx context.Context, msg *types.MsgPioneerUpdateEnclaveIdentity) (*types.MsgPioneerUpdateEnclaveIdentityResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	common.ContextDebug(ctx, "PioneerUpdateEnclaveIdentity")

	enclaveIdentity := types.EnclaveIdentity{
		UniqueID: msg.UniqueID,
		SignerID: msg.SignerID,
		Status:   msg.Status,
	}

	updateEnclaveIdentity := types.PioneerUpdateEnclaveIdentity{
		EnclaveIdentity: &enclaveIdentity,
		RemoteReport:    msg.RemoteReport,
	}

	err := k.Keeper.EnclaveClientUpdateEnclaveIdentity(ctx, updateEnclaveIdentity)

	if err != nil {
		return nil, err
	}

	k.Keeper.SetEnclaveIdentityNoEnclave(ctx, enclaveIdentity)

	return &types.MsgPioneerUpdateEnclaveIdentityResponse{}, nil
}
