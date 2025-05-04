package keeper

import (
	"context"

	"qadena_v3/x/qadena/types"

	"qadena_v3/x/qadena/common"

	"strings"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

func (k msgServer) PioneerUpdateIntervalPublicKeyID(goCtx context.Context, msg *types.MsgPioneerUpdateIntervalPublicKeyID) (*types.MsgPioneerUpdateIntervalPublicKeyIDResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	common.ContextDebug(ctx, "PioneerUpdateIntervalPublicKeyId")

	if !k.ClientVerifyRemoteReport(ctx, msg.RemoteReport, strings.Join([]string{
		msg.Creator,
		msg.PubKID,
		msg.NodeID,
		msg.NodeType,
		msg.ExternalIPAddress,
	}, "|")) {
		return nil, types.ErrInvalidEnclave
	}

	_, found := k.GetIntervalPublicKeyID(ctx, msg.NodeID, msg.NodeType)
	if found {
		common.ContextDebug(ctx, "...update...")
	} else {
		common.ContextDebug(ctx, "...set... "+msg.NodeID+" "+msg.NodeType+" "+msg.PubKID)
	}

	intervalPublicKeyId := types.IntervalPublicKeyID{
		PubKID:            msg.PubKID,
		NodeID:            msg.NodeID,
		NodeType:          msg.NodeType,
		ExternalIPAddress: msg.ExternalIPAddress,
		RemoteReport:      msg.RemoteReport,
	}

	k.Keeper.SetIntervalPublicKeyID(ctx, intervalPublicKeyId)

	return &types.MsgPioneerUpdateIntervalPublicKeyIDResponse{}, nil
}
