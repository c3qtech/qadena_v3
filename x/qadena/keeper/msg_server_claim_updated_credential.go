package keeper

import (
	"context"

	"github.com/c3qtech/qadena_v3/x/qadena/types"

	sdk "github.com/cosmos/cosmos-sdk/types"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"
)

// AUTHORIZATION:
//
//	the creator must be an ephemeral wallet, and the enclave must be able to prove that the
//	ephemeral wallet was created by somebody holding a key to the real wallet.  That proof needs
//	the encrypted createWallet vshare, so it can only happen inside the enclave.
//
// This exists because an ephemeral wallet's accept-list freezes each credential's Pedersen
// commitment at creation time.  An UpdateCredential that moves a name changes that commitment, and
// every ephemeral wallet accepting the corresponding sub-credential then fails closed.  This
// message is how the owner re-points them.
func (k msgServer) ClaimUpdatedCredential(goCtx context.Context, msg *types.MsgClaimUpdatedCredential) (*types.MsgClaimUpdatedCredentialResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	c.ContextDebug(ctx, "ClaimUpdatedCredential isCheckTx=", ctx.IsCheckTx())

	ephWallet, found := k.GetWallet(ctx, msg.Creator)
	if !found {
		c.ContextError(ctx, "Wallet not found "+msg.Creator)
		return nil, types.ErrWalletNotExists
	}

	if len(msg.EncAcceptValidatedCredentialsVShare) == 0 || msg.AcceptValidatedCredentialsVShareBind == nil {
		c.ContextError(ctx, "no accept-validated-credentials supplied")
		return nil, types.ErrInvalidVShare
	}

	// same audience as the accept-list published by CreateWallet: SS-only chain keys plus the
	// optional service providers.  If this differed, the enclave could not decrypt the result.
	requiredSSOnlyChainCCPubK := make([]c.VSharePubKInfo, 0)
	requiredSSOnlyChainCCPubK, err := MsgServerAppendRequiredChainCCPubK(ctx, requiredSSOnlyChainCCPubK, k.Keeper, "", false)
	if err != nil {
		c.ContextError(ctx, "RequiredChainCCPubK SS only err "+err.Error())
		return nil, err
	}

	optionalServiceProvidersCCPubK := make([]c.VSharePubKInfo, 0)
	optionalServiceProvidersCCPubK, err = MsgServerAppendOptionalServiceProvidersCCPubK(ctx, optionalServiceProvidersCCPubK, k.Keeper, ephWallet.ServiceProviderID, []string{types.FinanceServiceProvider})
	if err != nil {
		c.ContextError(ctx, "OptionalServiceProvidersCCPubK err "+err.Error())
		return nil, err
	}

	validatedCredentialsCCPubK := make([]c.VSharePubKInfo, 0)
	validatedCredentialsCCPubK = append(validatedCredentialsCCPubK, requiredSSOnlyChainCCPubK...)
	validatedCredentialsCCPubK = append(validatedCredentialsCCPubK, optionalServiceProvidersCCPubK...)

	if !c.ValidateVShare(ctx, msg.AcceptValidatedCredentialsVShareBind, msg.EncAcceptValidatedCredentialsVShare, validatedCredentialsCCPubK) {
		c.ContextError(ctx, "ValidatedCredentialsVShare err")
		return nil, types.ErrInvalidVShare
	}

	ret, err := k.EnclaveClientClaimUpdatedCredential(ctx, msg)
	if err != nil {
		c.ContextError(ctx, "EnclaveClientClaimUpdatedCredential "+err.Error())
		return nil, err
	}

	// the enclave rewrites its own copy of the wallet and the EndBlock sync carries it to the
	// chain, so there is deliberately no SetWallet here

	c.ContextDebug(ctx, "returning ok")

	return ret, nil
}
