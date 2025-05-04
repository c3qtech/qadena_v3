package keeper

import (
	"context"
	//	"math/big"
	"strconv"

	"github.com/c3qtech/qadena_v3/x/qadena/types"

	sdk "github.com/cosmos/cosmos-sdk/types"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"

	"cosmossdk.io/math"
)

func (k msgServer) TransferFunds(goCtx context.Context, msg *types.MsgTransferFunds) (*types.MsgTransferFundsResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	// get source wallet before any changes
	sourceWallet, found := k.GetWallet(ctx, msg.Creator)

	if !found {
		return nil, types.ErrWalletNotExists
	}

	dstCCPubK := make([]c.VSharePubKInfo, 0)
	// add optional service providers to ccPubK
	dstCCPubK, err := MsgServerAppendOptionalServiceProvidersCCPubK(ctx, dstCCPubK, k.Keeper, sourceWallet.ServiceProviderID, []string{types.FinanceServiceProvider})
	if err != nil {
		return nil, err
	}

	if !c.ValidateVShare(ctx, msg.TransferFundsVShareBind, msg.EncTransferFundsVShare, dstCCPubK) {
		return nil, types.ErrInvalidVShare
	}

	anonymizerCCPubK := make([]c.VSharePubKInfo, 0)

	anonymizerCCPubK, err = MsgServerAppendRequiredChainCCPubK(ctx, anonymizerCCPubK, k.Keeper, sourceWallet.HomePioneerID, true) // excludeSSIntervalPubK
	if err != nil {
		return nil, err
	}

	// add optional service providers to ccPubK
	anonymizerCCPubK, err = MsgServerAppendOptionalServiceProvidersCCPubK(ctx, anonymizerCCPubK, k.Keeper, sourceWallet.ServiceProviderID, []string{types.FinanceServiceProvider})
	if err != nil {
		return nil, err
	}

	if !c.ValidateVShare(ctx, msg.AnonTransferFundsVShareBind, msg.EncAnonTransferFundsVShare, anonymizerCCPubK) {
		return nil, types.ErrInvalidVShare
	}

	srcCCPubK := make([]c.VSharePubKInfo, 0)

	// add optional service providers to ccPubK
	srcCCPubK, err = MsgServerAppendOptionalServiceProvidersCCPubK(ctx, srcCCPubK, k.Keeper, sourceWallet.ServiceProviderID, []string{types.FinanceServiceProvider})
	if err != nil {
		return nil, err
	}

	if !c.ValidateVShare(ctx, msg.NewSourceWalletAmountVShareBind, msg.EncNewSourceWalletAmountVShare, srcCCPubK) {
		return nil, types.ErrInvalidVShare
	}

	unprotoSourcePC := c.UnprotoizeBPedersenCommit(msg.SourcePC)
	unprotoHiddenTransferPC := c.UnprotoizeBPedersenCommit(msg.HiddenTransferPC)
	unprotoNewSourcePC := c.UnprotoizeBPedersenCommit(msg.NewSourcePC)
	token := msg.TokenDenom

	if token == types.AQadenaTokenDenom {
		token = types.QadenaTokenDenom
	}

	// we should really scan after validating the transaction, but this is here for now unti we implement some kind of commit/rollback
	// in the enclave
	ok, err := k.ScanTransaction(ctx, msg)

	if !ok {
		c.ContextError(ctx, "ScanTransaction failed "+err.Error())
		return nil, err
	} else {
		c.ContextDebug(ctx, "ScanTransaction ok")
	}

	if msg.HiddenTransferPCProof != nil && msg.NewSourcePCProof != nil {
		unprotoHiddenTransferPCProof := c.UnprotoizeBRangeProof(msg.HiddenTransferPCProof)
		unprotoNewSourcePCProof := c.UnprotoizeBRangeProof(msg.NewSourcePCProof)

		/*
			c.ContextDebug(ctx, "received this transferPCProof:"+c.PrettyPrint(*msg.TransferPCProof))
			c.ContextDebug(ctx, "received this newSourcePCProof:"+c.PrettyPrint(*msg.NewSourcePCProof))
			c.ContextDebug(ctx, "received this unprotoTransferPCProof:"+c.PrettyPrint(unprotoTransferPCProof))
			c.ContextDebug(ctx, "received this unprotoNewSourcePCProof:"+c.PrettyPrint(unprotoNewSourcePCProof))
			c.ContextDebug(ctx, "versus:"+c.PrettyPrint(c.RangeProof{}))
		*/

		if !c.VerifyRangeProofV2(c.GetVectorBase(), unprotoHiddenTransferPC, unprotoHiddenTransferPCProof) {
			c.ContextDebug(ctx, "TranfserPCProof failed")
			return nil, types.ErrRangeProofValidation
		}

		if !c.VerifyRangeProofV2(c.GetVectorBase(), unprotoNewSourcePC, unprotoNewSourcePCProof) {
			c.ContextDebug(ctx, "NewSourcePCProof failed")
			return nil, types.ErrRangeProofValidation
		}
	}

	unprotoTransferFundsBindData := c.UnprotoizeVShareBindData(msg.TransferFundsVShareBind)
	/*
		// just checking to see if the bytes were transferred over with no problem
		c.ContextDebug(ctx, "E = "+c.PrettyPrint(hex.EncodeToString([]byte(msg.E))))
		for _, v := range unprotoBindData.R_ {
			c.ContextDebug(ctx, "BIND DATA R="+hex.EncodeToString(v)) // if you use PrettyPrint, it won't print right
		}
	*/
	// this node can do the bind verification but needs to look-up the public keys used to ensure that the client isn't cheating that way; it's an additional step and left for a future update
	if !unprotoTransferFundsBindData.VShareBVerify(msg.EncTransferFundsVShare) {
		c.ContextDebug(ctx, "VShareBVerify failed")
		return nil, types.ErrVShareVerification
	}

	c.ContextDebug(ctx, "Checking ValidateSubPedersenCommit")
	if !c.ValidateSubPedersenCommit(unprotoSourcePC, unprotoHiddenTransferPC, unprotoNewSourcePC) {
		return nil, types.ErrGenericPedersen
	}

	c.ContextDebug(ctx, "Valid")

	// check wether the wallet already supports the new token
	if _, ok = sourceWallet.WalletAmount[token]; ok {
		unprotoWalletAmountPedersenCommit := c.UnprotoizeBPedersenCommit(sourceWallet.WalletAmount[token].WalletAmountPedersenCommit)

		if !unprotoWalletAmountPedersenCommit.C.Equal(unprotoSourcePC.C) {
			c.ContextDebug(ctx, "commitment in TransferFunds transaction is different than what is stored in the wallet")
			return nil, types.ErrGenericPedersen
		}
	}

	c.ContextDebug(ctx, "locking bankPC amount "+c.UnprotoizeBInt(msg.TransparentAmount).String())

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
	err = k.lockAccountAmount(ctx, accountAddress, coinAmount)
	if err != nil {
		c.ContextError(ctx, "Could not lock coins from account "+coinAmount.String())
		return nil, err
	}

	// this validates the transferprime, but also may change the destination wallet
	mustUpdateSrcWallet, err := k.ValidateTransferPrime(ctx, msg)
	if err != nil {
		c.ContextError(ctx, "ValidateTransferPrime error "+err.Error())
		return nil, err
	}

	c.ContextDebug(ctx, "transfer prime validated, mustUpdateSrcWallet "+strconv.FormatBool(mustUpdateSrcWallet))

	// check if we should update the source wallet
	if mustUpdateSrcWallet {
		// yes, we should update the source wallet

		// get source wallet again because it may have been changed by ValidateTransferPrime
		sourceWallet, found = k.GetWallet(ctx, msg.Creator)

		if !found {
			return nil, types.ErrInvalidCreator
		}

		sourceWallet.WalletAmount[token] = &types.WalletAmount{
			WalletAmountPedersenCommit: msg.NewSourcePC,
			EncWalletAmountVShare:      msg.EncNewSourceWalletAmountVShare,
			WalletAmountVShareBind:     msg.NewSourceWalletAmountVShareBind,
		}

		c.ContextDebug(ctx, "new source wallet "+c.PrettyPrint(sourceWallet))

		k.SetWallet(ctx, sourceWallet)

		c.ContextDebug(ctx, "saved changes to the source wallet")
	} else {
		// no need to update

		c.ContextDebug(ctx, "skipped source wallet update")
	}

	return &types.MsgTransferFundsResponse{}, nil
}
