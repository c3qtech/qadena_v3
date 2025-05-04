package keeper

import (
	"context"

	"github.com/c3qtech/qadena_v3/x/qadena/common"
	"github.com/c3qtech/qadena_v3/x/qadena/types"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

func (k msgServer) AddPublicKey(goCtx context.Context, msg *types.MsgAddPublicKey) (*types.MsgAddPublicKeyResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	common.ContextDebug(ctx, "AddPublicKey")

	_, found := k.GetPublicKey(ctx, msg.Creator, msg.PubKType)
	if found {
		return nil, types.ErrPublicKeyAlreadyExists
	}

	publicKey := types.PublicKey{
		PubKID:   msg.Creator,
		PubK:     msg.PubK,
		PubKType: msg.PubKType,
	}

	/*
		err := publicKey.Validate()
		if err != nil {
			return nil, err
		}
	*/

	k.Keeper.SetPublicKey(ctx, publicKey)

	return &types.MsgAddPublicKeyResponse{}, nil
}
