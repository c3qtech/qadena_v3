package keeper

/*
import (
	"context"

	"qadena/x/qadena/types"

	sdk "github.com/cosmos/cosmos-sdk/types"

	c "qadena/x/qadena/common"
)

func (k msgServer) UpdateIntervalPublicKeyID(goCtx context.Context, msg *types.MsgUpdateIntervalPublicKeyID) (*types.MsgUpdateIntervalPublicKeyIDResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	c.ContextDebug(ctx, "UpdateIntervalPublicKeyId")

	_, found := k.GetIntervalPublicKeyID(ctx, msg.NodeID, msg.NodeType)
	if found {
		c.ContextDebug(ctx, "...update...")
	} else {
		c.ContextDebug(ctx, "...set...")
	}

	intervalPublicKeyId := types.IntervalPublicKeyID{
		PubKID:              msg.Creator,
		NodeID:              msg.NodeID,
		NodeType:            msg.NodeType,
		ServiceProviderType: msg.ServiceProviderType,
	}

	k.Keeper.SetIntervalPublicKeyID(ctx, intervalPublicKeyId)

	return &types.MsgUpdateIntervalPublicKeyIDResponse{}, nil
}
*/
