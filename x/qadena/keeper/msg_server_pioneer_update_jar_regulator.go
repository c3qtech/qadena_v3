package keeper

import (
	"context"

	"qadena_v3/x/qadena/types"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"qadena_v3/x/qadena/common"
	"strings"
)

func (k msgServer) PioneerUpdateJarRegulator(goCtx context.Context, msg *types.MsgPioneerUpdateJarRegulator) (*types.MsgPioneerUpdateJarRegulatorResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	common.ContextDebug(ctx, "UpdateJarRegulator")

	if !k.ClientVerifyRemoteReport(ctx, msg.RemoteReport, strings.Join([]string{
		msg.Creator,
		msg.JarID,
		msg.RegulatorID,
	}, "|")) {
		return nil, types.ErrInvalidEnclave
	}

	_, found := k.GetJarRegulator(ctx, msg.JarID)
	if found {
		common.ContextDebug(ctx, "...update...")
	} else {
		common.ContextDebug(ctx, "...set...")
	}

	jarRegulator := types.JarRegulator{
		JarID:        msg.JarID,
		RegulatorID:  msg.RegulatorID,
		RemoteReport: msg.RemoteReport,
	}

	k.Keeper.SetJarRegulator(ctx, jarRegulator)

	return &types.MsgPioneerUpdateJarRegulatorResponse{}, nil
}
