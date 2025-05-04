package keeper

import (
	"context"

	"qadena/x/qadena/types"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"encoding/json"
	"qadena/x/qadena/common"
	"strings"
)

func (k msgServer) PioneerAddPublicKey(goCtx context.Context, msg *types.MsgPioneerAddPublicKey) (*types.MsgPioneerAddPublicKeyResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	common.ContextDebug(ctx, "PioneerAddPublicKey")

	shares := ""
	if msg.Shares != nil {
		b, err := json.Marshal(msg.Shares)
		if err != nil {
			return nil, err
		}
		shares = string(b)
	}

	if !k.ClientVerifyRemoteReport(ctx, msg.RemoteReport, strings.Join([]string{
		msg.Creator,
		msg.PubKID,
		msg.PubK,
		msg.PubKType,
		shares,
	}, "|")) {
		return nil, types.ErrInvalidEnclave
	}

	_, found := k.GetPublicKey(ctx, msg.PubKID, msg.PubKType)
	if found {
		return nil, types.ErrPublicKeyAlreadyExists
	}

	publicKey := types.PublicKey{
		PubKID:       msg.PubKID,
		PubK:         msg.PubK,
		PubKType:     msg.PubKType,
		RemoteReport: msg.RemoteReport,
		Shares:       msg.Shares,
	}

	k.Keeper.SetPublicKey(ctx, publicKey)

	return &types.MsgPioneerAddPublicKeyResponse{}, nil
}
