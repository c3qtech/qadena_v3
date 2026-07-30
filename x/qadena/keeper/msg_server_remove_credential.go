package keeper

import (
	"context"

	"github.com/c3qtech/qadena_v3/x/qadena/types"

	sdk "github.com/cosmos/cosmos-sdk/types"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"
)

// AUTHORIZATION: either of two paths.
//
//	identity provider: the creator *IS* an identity service provider, and may only remove a
//	  credential nobody has claimed;
//	owner: the creator is the walletID recorded on the credential, and may remove it even though
//	  it is claimed -- it is theirs.
//
// The owner path exists so a user can drop a superseded contact credential after a correction.
// Personal-info is deliberately excluded: removing it would orphan wallet.credentialID and the
// identity hashes that anchor key recovery.
func (k msgServer) RemoveCredential(goCtx context.Context, msg *types.MsgRemoveCredential) (*types.MsgRemoveCredentialResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	c.ContextDebug(ctx, "remove credential", ctx.IsCheckTx(), msg.CredentialID, msg.CredentialType)

	credential, found := k.GetCredential(ctx, msg.CredentialID, msg.CredentialType)

	if !found {
		c.ContextDebug(ctx, "credential not found")
		return nil, types.ErrCredentialNotExists
	}

	isOwner := credential.WalletID != "" && credential.WalletID == msg.Creator

	var requesterWalletID string

	if isOwner {
		if msg.CredentialType == types.PersonalInfoCredentialType ||
			msg.CredentialType == types.FirstNamePersonalInfoCredentialType ||
			msg.CredentialType == types.MiddleNamePersonalInfoCredentialType ||
			msg.CredentialType == types.LastNamePersonalInfoCredentialType {
			c.ContextError(ctx, "cannot remove your own "+msg.CredentialType+"; it anchors your wallet and key recovery")
			return nil, types.ErrCredentialUpdateRejected
		}
		requesterWalletID = msg.Creator
	} else {
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

		if credential.WalletID != "" {
			c.ContextDebug(ctx, "credential claimed")
			return nil, types.ErrCredentialClaimed
		}
	}

	c.ContextDebug(ctx, "removing Credential "+msg.CredentialID+" "+msg.CredentialType)

	err := k.KeeperRemoveCredential(ctx, msg.CredentialID, msg.CredentialType, requesterWalletID)
	if err != nil {
		c.ContextError(ctx, "error removing credential "+err.Error())
		return nil, err
	}

	return &types.MsgRemoveCredentialResponse{}, nil
}
