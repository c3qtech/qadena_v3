package keeper

import (
	"context"

	"qadena/x/qadena/types"

	sdk "github.com/cosmos/cosmos-sdk/types"

	c "qadena/x/qadena/common"
)

func (k msgServer) SignRecoverPrivateKey(goCtx context.Context, msg *types.MsgSignRecoverPrivateKey) (*types.MsgSignRecoverPrivateKeyResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	ccPubK := make([]c.VSharePubKInfo, 0)

	ccPubK, err := MsgServerAppendRequiredChainCCPubK(ctx, ccPubK, k.Keeper, "", false)
	if err != nil {
		return nil, err
	}

	if !c.ValidateVShare(ctx, msg.DestinationEWalletIDVShareBind, msg.EncDestinationEWalletIDVShare, ccPubK) {
		return nil, types.ErrInvalidVShare
	}

	err = k.EnclaveClientSignRecoverKey(ctx, *msg)

	if err != nil {
		c.ContextError(ctx, "EnclaveClientSignRecoverKey "+err.Error())
		return nil, err
	}

	return &types.MsgSignRecoverPrivateKeyResponse{}, nil
}
