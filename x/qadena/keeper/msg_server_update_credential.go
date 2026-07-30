package keeper

import (
	"context"

	"github.com/c3qtech/qadena_v3/x/qadena/types"

	sdk "github.com/cosmos/cosmos-sdk/types"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"
)

// AUTHORIZATION:
//
//	the creator must already own the credential being updated
//
// This is the mirror image of ClaimCredential: claim rejects a credentialID that already exists,
// update requires one.  The ownership check works in the clear because Credential.walletID is
// plaintext on chain and kept current by the EndBlock sync, so an unauthorized update is rejected
// here without ever reaching the enclave.
func (k msgServer) UpdateCredential(goCtx context.Context, msg *types.MsgUpdateCredential) (*types.MsgUpdateCredentialResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	c.ContextDebug(ctx, "UpdateCredential isCheckTx=", ctx.IsCheckTx())

	walletID := msg.Creator

	wallet, found := k.GetWallet(ctx, walletID)
	if !found {
		c.ContextError(ctx, "Wallet not found "+walletID)
		return nil, types.ErrWalletNotExists
	}

	credential, found := k.GetCredential(ctx, msg.CredentialID, msg.CredentialType)
	if !found {
		c.ContextError(ctx, "Credential not found "+msg.CredentialID+" "+msg.CredentialType)
		return nil, types.ErrCredentialNotExists
	}

	if credential.WalletID != msg.Creator {
		c.ContextError(ctx, "Credential "+msg.CredentialID+" is owned by "+credential.WalletID+", not "+msg.Creator)
		return nil, types.ErrCredentialUpdateNotOwner
	}

	// The wallet must point back at the credential.  Ownership is recorded on both rows and an
	// update must never be able to move wallet.credentialID, so a disagreement here is a bug we
	// refuse to paper over.
	if wallet.CredentialID != msg.CredentialID {
		c.ContextError(ctx, "Wallet "+walletID+" credentialID "+wallet.CredentialID+" does not match "+msg.CredentialID)
		return nil, types.ErrCredentialUpdateNotOwner
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

	if !c.ValidateVShare(ctx, msg.UpdateCredentialExtraParmsVShareBind, msg.EncUpdateCredentialExtraParmsVShare, credentialCCPubK) {
		return nil, types.ErrInvalidVShare
	}

	moduleParams := k.GetParams(ctx)

	if err := k.consumeUpdateCredentialFee(ctx, moduleParams); err != nil {
		return nil, err
	}

	ret, err := k.EnclaveClientUpdateCredential(ctx, msg, moduleParams)
	if err != nil {
		c.ContextError(ctx, "EnclaveClientUpdateCredential "+err.Error())
		return nil, err
	}

	c.ContextDebug(ctx, "returning ok")

	return ret, nil
}

// consumeUpdateCredentialFee charges updateCredentialFee as gas.
//
// Deliberately no royalty split, unlike CreateCredential: those percentages key off the
// eKYCAppWalletID and referenceCredentialID of the identity provider's ownerless credential, and
// the provider already paid createCredentialFee and triggered those royalties when it published
// the correction.  Running them again here would pay twice for one issuance.
func (k msgServer) consumeUpdateCredentialFee(ctx sdk.Context, moduleParams types.Params) error {
	updateCredentialFee := c.UpdateCredentialFeeFromParams(moduleParams)

	c.ContextDebug(ctx, "updateCredentialFee "+updateCredentialFee)

	updateCredentialFeeCoin, err := sdk.ParseDecCoin(updateCredentialFee)
	if err != nil {
		c.ContextError(ctx, "error parsing coin "+err.Error())
		return err
	}

	// Convert a fiat-denominated fee through the pricefeed, the same way CreateCredential does.
	// Fails closed when there is no usable price -- see ExchangeRateToQadena for why substituting
	// zero here was unsafe.
	updateCredentialFeeCoin, err = k.ConvertFeeToQadena(ctx, updateCredentialFeeCoin)
	if err != nil {
		return err
	}

	gas := updateCredentialFeeCoin.Amount.Quo(c.GasPriceInAQDN)

	gasAsCoin, err := sdk.ParseCoinNormalized(gas.String() + types.QadenaTokenDenom)
	if err != nil {
		c.ContextError(ctx, "error parsing gasAsCoin", err.Error())
		return err
	}

	c.ContextDebug(ctx, "updateCredential gas", gasAsCoin.String())

	var gasAsUint64 uint64
	if gasAsCoin.Amount.IsInt64() {
		gasAsUint64 = gasAsCoin.Amount.Uint64()
	} else {
		gasAsUint64 = ctx.GasMeter().Limit()
	}

	ctx.GasMeter().ConsumeGas(gasAsUint64, "updateCredential")

	return nil
}
