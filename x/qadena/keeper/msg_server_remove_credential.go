package keeper

import (
	"context"

	"github.com/c3qtech/qadena_v3/x/qadena/types"

	sdk "github.com/cosmos/cosmos-sdk/types"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"
)

// AUTHORIZATION:
//
//	make sure that the creator *IS* an identity service provider
//	make sure that all the required signatory vshares ccPubK has ss interval public key
func (k msgServer) RemoveCredential(goCtx context.Context, msg *types.MsgRemoveCredential) (*types.MsgRemoveCredentialResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	c.ContextDebug(ctx, "remove credential", ctx.IsCheckTx(), msg.CredentialID, msg.CredentialType)

	// check if the creator is an identity service provider
	err := k.AuthenticateServiceProvider(ctx, msg.Creator, types.IdentityServiceProvider)
	if err != nil {
		return nil, err
	}

	ccPubK := make([]c.VSharePubKInfo, 0)

	ccPubK, err = MsgServerAppendRequiredChainCCPubK(ctx, ccPubK, k.Keeper, "", false)

	if err != nil {
		return nil, err
	}

	credential, found := k.GetCredential(ctx, msg.CredentialID, msg.CredentialType)

	if !found {
		c.ContextDebug(ctx, "credential not found")
		return nil, types.ErrCredentialNotExists
	}

	if credential.WalletID != "" {
		c.ContextDebug(ctx, "credential claimed")
		return nil, types.ErrCredentialClaimed
	}

	c.ContextDebug(ctx, "removing Credential "+msg.CredentialID+" "+msg.CredentialType)

	err = k.KeeperRemoveCredential(ctx, msg.CredentialID, msg.CredentialType)
	if err != nil {
		c.ContextError(ctx, "error removing credential "+err.Error())
		return nil, err
	}

	return &types.MsgRemoveCredentialResponse{}, nil
}
