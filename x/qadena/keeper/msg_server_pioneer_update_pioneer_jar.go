package keeper

import (
	"context"

	"github.com/c3qtech/qadena_v3/x/qadena/types"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"strings"

	"github.com/c3qtech/qadena_v3/x/qadena/common"
)

func (k msgServer) PioneerUpdatePioneerJar(goCtx context.Context, msg *types.MsgPioneerUpdatePioneerJar) (*types.MsgPioneerUpdatePioneerJarResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	common.ContextDebug(ctx, "UpdatePioneerJar")

	if !k.ClientVerifyRemoteReport(ctx, msg.RemoteReport, strings.Join([]string{
		msg.Creator,
		msg.PioneerID,
		msg.JarID,
	}, "|")) {
		return nil, types.ErrInvalidEnclave
	}

	_, found := k.GetPioneerJar(ctx, msg.PioneerID)
	if found {
		common.ContextDebug(ctx, "...update...")
	} else {
		common.ContextDebug(ctx, "...set...")
	}

	pioneerJar := types.PioneerJar{
		PioneerID:    msg.PioneerID,
		JarID:        msg.JarID,
		RemoteReport: msg.RemoteReport,
	}

	k.Keeper.SetPioneerJar(ctx, pioneerJar)

	return &types.MsgPioneerUpdatePioneerJarResponse{}, nil
}
