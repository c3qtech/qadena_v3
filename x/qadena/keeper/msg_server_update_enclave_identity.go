package keeper

import (
	"context"

	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"qadena_v3/x/qadena/common"

	"qadena_v3/x/qadena/types"
)

func (k msgServer) UpdateEnclaveIdentity(goCtx context.Context, msg *types.MsgUpdateEnclaveIdentity) (*types.MsgUpdateEnclaveIdentityResponse, error) {
	if k.GetAuthority() != msg.Authority {
		return nil, errorsmod.Wrapf(types.ErrInvalidSigner, "invalid authority; expected %s, got %s", k.GetAuthority(), msg.Authority)
	}

	ctx := sdk.UnwrapSDKContext(goCtx)

	common.ContextDebug(ctx, "UpdateEnclaveIdentity")

	_, found := k.GetEnclaveIdentity(ctx, msg.UniqueID)
	if found {
		common.ContextDebug(ctx, "...update..."+msg.UniqueID+" "+msg.SignerID+" "+msg.Status)
		if msg.Status != types.InactiveStatus {
			return nil, errorsmod.Wrapf(types.ErrInvalidStatus, "invalid status; expected %s, got %s", types.InactiveStatus, msg.Status)
		}
	} else {
		common.ContextDebug(ctx, "...set... "+msg.UniqueID+" "+msg.SignerID+" "+msg.Status)
		if msg.Status != types.UnvalidatedStatus {
			return nil, errorsmod.Wrapf(types.ErrInvalidStatus, "invalid status; expected %s, got %s", types.UnvalidatedStatus, msg.Status)
		}
	}

	enclaveIdentity := types.EnclaveIdentity{
		UniqueID: msg.UniqueID,
		SignerID: msg.SignerID,
		Status:   msg.Status,
	}

	k.Keeper.SetEnclaveIdentity(ctx, enclaveIdentity)

	return &types.MsgUpdateEnclaveIdentityResponse{}, nil
}
