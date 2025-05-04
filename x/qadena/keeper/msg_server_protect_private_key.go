package keeper

import (
	"context"

	"github.com/c3qtech/qadena_v3/x/qadena/types"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

func (k msgServer) ProtectPrivateKey(goCtx context.Context, msg *types.MsgProtectPrivateKey) (*types.MsgProtectPrivateKeyResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	walletID := msg.Creator

	c.ContextDebug(ctx, "Protect Key "+walletID)

	// go through
	pk := types.ProtectKey{WalletID: walletID,
		Threshold:    msg.Threshold,
		RecoverShare: msg.RecoverShare,
	}

	c.ContextDebug(ctx, "ProtectKey "+c.PrettyPrint(pk))

	k.SetProtectKey(ctx, pk)

	return &types.MsgProtectPrivateKeyResponse{}, nil
}
