package keeper

import (
	"context"
	//	"math/big"
	"strconv"

	"qadena/x/qadena/types"

	sdk "github.com/cosmos/cosmos-sdk/types"

	c "qadena/x/qadena/common"

	"cosmossdk.io/math"
)

func (k msgServer) ReceiveFunds(goCtx context.Context, msg *types.MsgReceiveFunds) (*types.MsgReceiveFundsResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	// get dst wallet before any changes
	dstWallet, found := k.GetWallet(ctx, msg.Creator)
	if !found {
		return nil, types.ErrWalletNotExists
	}

	// this needs jar/anonymizer and optional finance service providers
	anonymizerCCPubK := make([]c.VSharePubKInfo, 0)

	anonymizerCCPubK, err := MsgServerAppendRequiredChainCCPubK(ctx, anonymizerCCPubK, k.Keeper, dstWallet.HomePioneerID, true) // excludeSSIntervalPubK
	if err != nil {
		return nil, err
	}

	// add optional service providers to ccPubK
	anonymizerCCPubK, err = MsgServerAppendOptionalServiceProvidersCCPubK(ctx, anonymizerCCPubK, k.Keeper, dstWallet.ServiceProviderID, []string{types.FinanceServiceProvider})
	if err != nil {
		return nil, err
	}

	if !c.ValidateVShare(ctx, msg.AnonReceiveFundsVShareBind, msg.EncAnonReceiveFundsVShare, anonymizerCCPubK) {
		return nil, types.ErrInvalidVShare
	}

	dstCCPubK := make([]c.VSharePubKInfo, 0)

	// add optional service providers to ccPubK
	dstCCPubK, err = MsgServerAppendOptionalServiceProvidersCCPubK(ctx, dstCCPubK, k.Keeper, dstWallet.ServiceProviderID, []string{types.FinanceServiceProvider})
	if err != nil {
		return nil, err
	}

	if !c.ValidateVShare(ctx, msg.NewDestinationWalletAmountVShareBind, msg.EncNewDestinationWalletAmountVShare, dstCCPubK) {
		return nil, types.ErrInvalidVShare
	}

	receiveFundsCCPubK := make([]c.VSharePubKInfo, 0)

	receiveFundsCCPubK, err = MsgServerAppendRequiredChainCCPubK(ctx, receiveFundsCCPubK, k.Keeper, dstWallet.HomePioneerID, true) // excludeSSIntervalPubK
	if err != nil {
		return nil, err
	}

	// add optional service providers to ccPubK
	receiveFundsCCPubK, err = MsgServerAppendOptionalServiceProvidersCCPubK(ctx, receiveFundsCCPubK, k.Keeper, dstWallet.ServiceProviderID, []string{types.FinanceServiceProvider})
	if err != nil {
		return nil, err
	}

	if !c.ValidateVShare(ctx, msg.ReceiveFundsVShareBind, msg.EncReceiveFundsVShare, receiveFundsCCPubK) {
		return nil, types.ErrInvalidVShare
	}

	// validate incoming PCs
	unprotoDestinationPC := c.UnprotoizeBPedersenCommit(msg.DestinationPC)
	unprotoTransferPC := c.UnprotoizeBPedersenCommit(msg.HiddenTransferPC)
	unprotoNewDestinationPC := c.UnprotoizeBPedersenCommit(msg.NewDestinationPC)
	token := msg.TokenDenom

	if token == types.AQadenaTokenDenom {
		token = types.QadenaTokenDenom
	}

	// check wether the wallet already supports the new token
	if _, ok := dstWallet.EphemeralWalletAmountCount[token]; !ok {
		// let's add the unsupported token into the wallet
		if dstWallet.EphemeralWalletAmountCount[types.QadenaTokenDenom] == types.QadenaRealWallet {
			dstWallet.EphemeralWalletAmountCount[token] = types.QadenaRealWallet
		} else {
			dstWallet.EphemeralWalletAmountCount[token] = 0
		}
	}

	if msg.HiddenTransferPCProof != nil && msg.NewDestinationPCProof != nil {
		// check the range proof here
		unprotoTransferPCProof := c.UnprotoizeBRangeProof(msg.HiddenTransferPCProof)
		unprotoNewDestinationPCProof := c.UnprotoizeBRangeProof(msg.NewDestinationPCProof)

		if !c.VerifyRangeProofV2(c.GetVectorBase(), unprotoTransferPC, unprotoTransferPCProof) {
			return nil, types.ErrRangeProofValidation
		}

		if !c.VerifyRangeProofV2(c.GetVectorBase(), unprotoNewDestinationPC, unprotoNewDestinationPCProof) {
			return nil, types.ErrRangeProofValidation
		}
	}

	unprotoReceiveFundsBindData := c.UnprotoizeVShareBindData(msg.ReceiveFundsVShareBind)

	// this node can do the bind verification but needs to look-up the public keys used to ensure that the client isn't cheating that way; it's an additional step and left for a future update

	if !unprotoReceiveFundsBindData.VShareBVerify(msg.EncReceiveFundsVShare) {
		c.ContextDebug(ctx, "VShareBVerify failed")
		return nil, types.ErrVShareVerification
	}

	if dstWallet.EphemeralWalletAmountCount[token] == types.QadenaRealWallet {
		c.ContextDebug(ctx, "Real wallet, checking ValidateAddPedersenCommit")
		if !c.ValidateAddPedersenCommit(unprotoDestinationPC, unprotoTransferPC, unprotoNewDestinationPC) {
			return nil, types.ErrGenericPedersen
		}
	} else {
		c.ContextDebug(ctx, "Eph wallet, checking ValidateSubPedersenCommit")
		if !c.ValidateSubPedersenCommit(unprotoDestinationPC, unprotoTransferPC, unprotoNewDestinationPC) {
			return nil, types.ErrGenericPedersen
		}
	}

	c.ContextDebug(ctx, "Valid")

	// check wether the wallet already supports the new token
	if _, ok := dstWallet.WalletAmount[token]; ok {
		unprotoWalletAmountPedersenCommit := c.UnprotoizeBPedersenCommit(dstWallet.WalletAmount[token].WalletAmountPedersenCommit)

		if !unprotoWalletAmountPedersenCommit.C.Equal(unprotoDestinationPC.C) {
			c.ContextDebug(ctx, "commitment does not match what's in the wallet")
			return nil, types.ErrGenericPedersen
		}
	}

	accountAddress, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return nil, types.ErrInvalidCreator
	}

	bankTransparentAmount := c.UnprotoizeBInt(msg.TransparentAmount)

	bankTokenDenom := token
	if token == types.QadenaTokenDenom {
		bankTokenDenom = types.AQadenaTokenDenom
	}

	coinAmount := sdk.NewCoin(bankTokenDenom, math.NewIntFromBigInt(bankTransparentAmount))
	err = k.unlockAccountAmount(ctx, accountAddress, coinAmount)
	if err != nil {
		c.ContextDebug(ctx, "Could not lock coins from account "+coinAmount.String())
		return nil, err
	}

	mustUpdateDstWallet, err := k.ValidateTransferDoublePrime(ctx, msg)

	if err != nil {
		c.ContextDebug(ctx, "did not, or could not, validate transfer double prime")
		return nil, err
	}

	c.ContextDebug(ctx, "validated transfer double prime, mustUpdateDstWallet "+strconv.FormatBool(mustUpdateDstWallet))

	c.ContextDebug(ctx, "unlocking bankPC amount "+c.UnprotoizeBInt(msg.TransparentAmount).String())

	// check if we should update the destination wallet
	if mustUpdateDstWallet {
		// yes, update dst wallet

		// note that we do not need to get the dst wallet from the keeper again because ValidateTransferDoublePrime() didn't change it

		dstWallet.WalletAmount[token] = &types.WalletAmount{
			WalletAmountPedersenCommit: msg.NewDestinationPC,
			EncWalletAmountVShare:      msg.EncNewDestinationWalletAmountVShare,
			WalletAmountVShareBind:     msg.NewDestinationWalletAmountVShareBind,
		}

		c.ContextDebug(ctx, "new dst wallet "+c.PrettyPrint(dstWallet))

		k.SetWallet(ctx, dstWallet)
	} else {
		c.ContextDebug(ctx, "skipped wallet update, it was updated already by ValidateTransferDoublePrime()")
	}

	return &types.MsgReceiveFundsResponse{}, nil
}
