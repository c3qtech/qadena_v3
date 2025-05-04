package keeper

import (
	"context"

	"qadena_v3/x/qadena/types"

	sdk "github.com/cosmos/cosmos-sdk/types"

	c "qadena_v3/x/qadena/common"
)

func (k msgServer) ClaimCredential(goCtx context.Context, msg *types.MsgClaimCredential) (*types.MsgClaimCredentialResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	walletID := msg.Creator

	wallet, found := k.GetWallet(ctx, walletID)

	if !found {
		c.ContextError(ctx, "Wallet not found "+walletID)
		return nil, types.ErrWalletNotExists
	}

	_, found = k.GetCredential(ctx, msg.CredentialID, msg.CredentialType)
	if found {
		c.ContextError(ctx, "Credential already exists "+msg.CredentialID+" "+msg.CredentialType)
		return nil, types.ErrCredentialExists
	}

	requiredChainCCPubK := make([]c.VSharePubKInfo, 0)
	requiredChainCCPubK, err := MsgServerAppendRequiredChainCCPubK(ctx, requiredChainCCPubK, k.Keeper, "", false)
	if err != nil {
		c.ContextError(ctx, "RequiredChainCCPubK err "+err.Error())
		return nil, err
	}
	optionalServiceProvidersCCPubK := make([]c.VSharePubKInfo, 0)
	optionalServiceProvidersCCPubK, err = MsgServerAppendOptionalServiceProvidersCCPubK(ctx, optionalServiceProvidersCCPubK, k.Keeper, wallet.ServiceProviderID, []string{types.FinanceServiceProvider})
	if err != nil {
		c.ContextError(ctx, "OptionalServiceProvidersCCPubK err "+err.Error())
		return nil, err
	}

	credentialCCPubK := make([]c.VSharePubKInfo, 0)
	credentialCCPubK = append(credentialCCPubK, requiredChainCCPubK...)
	credentialCCPubK = append(credentialCCPubK, optionalServiceProvidersCCPubK...)

	if !c.ValidateVShare(ctx, msg.ClaimCredentialExtraParmsVShareBind, msg.EncClaimCredentialExtraParmsVShare, credentialCCPubK) {
		return nil, types.ErrInvalidVShare
	}

	//	if credential.WalletID != "" {
	//		return nil, types.ErrCredentialClaimed
	//	}

	ret, err := k.EnclaveClientClaimCredential(ctx, msg)

	if err != nil {
		c.ContextError(ctx, "EnclaveClientClaimCredential "+err.Error())
		return nil, err
	}

	c.ContextDebug(ctx, "returning ok")

	return ret, nil
}
