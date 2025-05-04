package keeper

import (
	"context"
	"fmt"

	// "math/big"

	"qadena/x/qadena/types"

	//sdkerrors "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"

	c "qadena/x/qadena/common"
)

func (k msgServer) CreateWallet(goCtx context.Context, msg *types.MsgCreateWallet) (*types.MsgCreateWalletResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	walletID := msg.Creator

	_, found := k.GetWallet(ctx, walletID)

	c.ContextDebug(ctx, "CreateWallet", walletID, "isCheckTx", ctx.IsCheckTx())

	if found {
		c.ContextDebug(ctx, "Wallet already exists "+walletID)
		return nil, types.ErrWalletExists
	}

	moduleParams := k.GetParams(ctx)

	requiredChainCCPubK := make([]c.VSharePubKInfo, 0)
	requiredChainCCPubK, err := MsgServerAppendRequiredChainCCPubK(ctx, requiredChainCCPubK, k.Keeper, msg.HomePioneerID, false)
	if err != nil {
		c.ContextError(ctx, "RequiredChainCCPubK err "+err.Error())
		return nil, err
	}
	requiredSSOnlyChainCCPubK := make([]c.VSharePubKInfo, 0)
	requiredSSOnlyChainCCPubK, err = MsgServerAppendRequiredChainCCPubK(ctx, requiredSSOnlyChainCCPubK, k.Keeper, "", false)
	if err != nil {
		c.ContextError(ctx, "RequiredChainCCPubK SS only err "+err.Error())
		return nil, err
	}

	optionalServiceProvidersCCPubK := make([]c.VSharePubKInfo, 0)
	optionalServiceProvidersCCPubK, err = MsgServerAppendOptionalServiceProvidersCCPubK(ctx, optionalServiceProvidersCCPubK, k.Keeper, msg.ServiceProviderID, []string{types.FinanceServiceProvider})
	if err != nil {
		c.ContextError(ctx, "OptionalServiceProvidersCCPubK err "+err.Error())
		return nil, err
	}

	if msg.AcceptValidatedCredentialsVShareBind != nil && msg.EncAcceptValidatedCredentialsVShare != nil && len(msg.EncAcceptValidatedCredentialsVShare) > 0 {
		validatedCredentialsCCPubK := make([]c.VSharePubKInfo, 0)

		validatedCredentialsCCPubK = append(validatedCredentialsCCPubK, requiredSSOnlyChainCCPubK...)
		validatedCredentialsCCPubK = append(validatedCredentialsCCPubK, optionalServiceProvidersCCPubK...)

		if !c.ValidateVShare(ctx, msg.AcceptValidatedCredentialsVShareBind, msg.EncAcceptValidatedCredentialsVShare, validatedCredentialsCCPubK) {
			c.ContextError(ctx, "ValidatedCredentialsVShare err")
			return nil, types.ErrInvalidVShare
		}
	}

	walletAmountCCPubK := make([]c.VSharePubKInfo, 0)
	walletAmountCCPubK = append(walletAmountCCPubK, optionalServiceProvidersCCPubK...)

	if !c.ValidateVShare(ctx, msg.WalletAmountVShareBind, msg.EncWalletAmountVShare, walletAmountCCPubK) {
		c.ContextError(ctx, "WalletAmountVShare err")
		return nil, types.ErrInvalidVShare
	}

	createWalletCCPubK := make([]c.VSharePubKInfo, 0)

	createWalletCCPubK = append(createWalletCCPubK, requiredChainCCPubK...)
	createWalletCCPubK = append(createWalletCCPubK, optionalServiceProvidersCCPubK...)

	if !c.ValidateVShare(ctx, msg.CreateWalletVShareBind, msg.EncCreateWalletVShare, createWalletCCPubK) {
		c.ContextError(ctx, "CreateWalletVShare err")
		return nil, types.ErrInvalidVShare
	}

	walletType, err := k.ValidateDestinationWallet(ctx, msg)
	if err != nil {
		c.ContextError(ctx, "Destination wallet invalid")
		return nil, err
	}

	var walletAmountPC *c.PedersenCommit = c.UnprotoizeEncryptablePedersenCommit(msg.WalletAmountPedersenCommit)
	var transparentWalletAmountPC *c.PedersenCommit = c.UnprotoizeEncryptablePedersenCommit(msg.TransparentWalletAmountPC)

	if !c.ValidatePedersenCommit(walletAmountPC) {
		c.ContextError(ctx, "Wallet amount invalid "+c.PrettyPrint(walletAmountPC))
		return nil, types.ErrGenericPedersen
	}

	var ephemeralWalletAmountCount = make(map[string]int32)
	ephemeralWalletAmountCount[types.QadenaTokenDenom] = types.QadenaRealWallet // by default create-wallet will create a real wallet
	// used to track the number of wallet amounts that were sent to this ephemeral wallet

	c.ContextDebug(ctx, "walletAmountPC "+c.PrettyPrint(walletAmountPC))
	c.ContextDebug(ctx, "transparentWalletAmountPC "+c.PrettyPrint(transparentWalletAmountPC))

	fmt.Println("nodeparams", k.nodeParams, "wallettype", walletType)

	accountAddress, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		c.ContextDebug(ctx, "Invalid creator "+msg.Creator)
		return nil, types.ErrInvalidCreator
	}

	incentiveCoin := moduleParams.GetCreateWalletIncentive()
	ephemeralIncentiveCoin := moduleParams.GetCreateEphemeralWalletIncentive()
	incentiveTransparentCoin := moduleParams.GetCreateWalletTransparentIncentive()
	ephemeralIncentiveTransparentCoin := moduleParams.GetCreateEphemeralWalletTransparentIncentive()

	incentiveCoin = sdk.NormalizeCoin(incentiveCoin)
	ephemeralIncentiveCoin = sdk.NormalizeCoin(ephemeralIncentiveCoin)
	incentiveTransparentCoin = sdk.NormalizeCoin(incentiveTransparentCoin)
	ephemeralIncentiveTransparentCoin = sdk.NormalizeCoin(ephemeralIncentiveTransparentCoin)

	c.ContextDebug(ctx, "incentiveCoin "+incentiveCoin.String())
	c.ContextDebug(ctx, "ephemeralIncentiveCoin "+ephemeralIncentiveCoin.String())
	c.ContextDebug(ctx, "incentiveTransparentCoin "+incentiveTransparentCoin.String())
	c.ContextDebug(ctx, "ephemeralIncentiveTransparentCoin "+ephemeralIncentiveTransparentCoin.String())

	if walletType == types.WalletTypeReal {
		c.ContextDebug(ctx, "Real wallet")
		// validate
		if walletAmountPC.A.Cmp(incentiveCoin.Amount.BigInt()) != 0 || transparentWalletAmountPC.A.Cmp(incentiveTransparentCoin.Amount.BigInt()) != 0 {
			c.ContextDebug(ctx, "Wallet is trying to cheat, incentive mismatch", incentiveCoin.Amount, transparentWalletAmountPC.A)
			return nil, types.ErrGenericTransaction
		}
		// how much we will transfer into the new wallet (incentive)

		c.ContextDebug(ctx, "transfer from Treasury to QADENA module for encrypted amount "+c.PrettyPrint(incentiveCoin))
		err = k.lockAccountAmount(ctx, k.getTreasuryAddress(ctx), incentiveCoin)
		if err != nil {
			c.ContextError(ctx, "err transfer (lockAccountAmount) "+err.Error())
			return nil, types.ErrGenericTreasury
		}
		c.ContextDebug(ctx, "coins locked for encrypted amount")

		// transfer the transparent incentive from treasury to our transparent address
		err = k.distributeIncentives(ctx, accountAddress, incentiveTransparentCoin)

		if err != nil {
			c.ContextError(ctx, "err transfer (distributeIncentives) "+err.Error())
			return nil, types.ErrGenericTreasury
		}

		c.ContextDebug(ctx, "distributed incentive coins")
	} else if walletType == types.WalletTypeEphemeral {
		c.ContextDebug(ctx, "Ephemeral wallet")
		// we're creating an ephemeral wallet
		ephemeralWalletAmountCount[types.QadenaTokenDenom] = 0 // used to track the number of wallet amounts that were sent to this ephemeral wallet

		// validate
		if walletAmountPC.A.Cmp(ephemeralIncentiveCoin.Amount.BigInt()) != 0 || transparentWalletAmountPC.A.Cmp(ephemeralIncentiveTransparentCoin.Amount.BigInt()) != 0 {
			c.ContextError(ctx, "Wallet is trying to cheat, incentive mismatch", ephemeralIncentiveCoin.Amount, transparentWalletAmountPC.A)
			return nil, types.ErrGenericTransaction
		}
		// how much we will transfer into the new wallet (incentive)

		c.ContextDebug(ctx, "transfer from Treasury to QADENA module for encrypted amount "+c.PrettyPrint(ephemeralIncentiveCoin))
		err = k.lockAccountAmount(ctx, k.getTreasuryAddress(ctx), ephemeralIncentiveCoin)
		if err != nil {
			c.ContextError(ctx, "err transfer (lockAccountAmount) "+err.Error())
			return nil, types.ErrGenericTreasury
		}
		c.ContextDebug(ctx, "coins locked for encrypted amount")

		// transfer the transparent incentive from treasury to our transparent address
		err = k.distributeIncentives(ctx, accountAddress, ephemeralIncentiveTransparentCoin)

		if err != nil {
			c.ContextError(ctx, "err transfer (distributeIncentives) "+err.Error())
			return nil, types.ErrGenericTreasury
		}

		c.ContextDebug(ctx, "distributed incentive coins")
	} else if walletType == types.WalletTypeCheckTx {
		c.ContextDebug(ctx, "wallet type is WalletTypeCheckTx")

		c.ContextDebug(ctx, "CHECKTX:  transfer from Treasury to QADENA module for encrypted amount "+c.PrettyPrint(incentiveCoin))
		err = k.lockAccountAmount(ctx, k.getTreasuryAddress(ctx), incentiveCoin)
		if err != nil {
			c.ContextError(ctx, "CHECKTX:  err transfer (lockAccountAmount) "+err.Error())
			return nil, types.ErrGenericTreasury
		}
		c.ContextDebug(ctx, "CHECKTX:  coins locked for encrypted amount")

		// transfer the transparent incentive from treasury to our transparent address
		err = k.distributeIncentives(ctx, accountAddress, incentiveTransparentCoin)

		if err != nil {
			c.ContextError(ctx, "CHECKTX:  err transfer (distributeIncentives) "+err.Error())
			return nil, types.ErrGenericTreasury
		}

		c.ContextDebug(ctx, "CHECKTX:  distributed incentive coins")

	} else {
		c.ContextError(ctx, "invalid dst wallet ID "+types.ErrInvalidDstEWalletID.Error())
		return nil, types.ErrInvalidDstEWalletID
	}

	emptyListWalletAmount := make(map[string]*types.ListWalletAmount)
	emptyListWalletAmount[types.QadenaTokenDenom] = &types.ListWalletAmount{WalletAmounts: []*types.WalletAmount{}}

	var walletAmountMap = make(map[string]*types.WalletAmount)
	walletAmountMap["default"] = &types.WalletAmount{}

	// check if walletAmountPC has incentives
	//if walletAmountPC.A.Cmp(c.BigIntZero) == +1 {
	walletAmountPC.A = c.BigIntZero
	walletAmountPC.X = c.BigIntZero

	protoWalletAmountPC := c.ProtoizeBPedersenCommit(walletAmountPC)
	wa := types.WalletAmount{WalletAmountPedersenCommit: protoWalletAmountPC,
		EncWalletAmountVShare:  msg.EncWalletAmountVShare,
		WalletAmountVShareBind: msg.WalletAmountVShareBind,
		RequiredSenderCheckPC:  []*types.BPedersenCommit{},
	}
	walletAmountMap[types.QadenaTokenDenom] = &wa
	//}

	recoverShares := make([]*types.RecoverShare, 0)

	c.ContextDebug(ctx, "Creating Wallet")

	w := types.Wallet{WalletID: walletID,
		HomePioneerID:                        msg.HomePioneerID,
		ServiceProviderID:                    msg.ServiceProviderID,
		WalletAmount:                         walletAmountMap,
		CredentialID:                         "",
		EncCreateWalletVShare:                msg.EncCreateWalletVShare,
		CreateWalletVShareBind:               msg.CreateWalletVShareBind,
		EphemeralWalletAmountCount:           ephemeralWalletAmountCount,
		QueuedWalletAmount:                   emptyListWalletAmount,
		AcceptPasswordPedersenCommit:         msg.AcceptPasswordPC,
		EncAcceptValidatedCredentialsVShare:  msg.EncAcceptValidatedCredentialsVShare,
		AcceptValidatedCredentialsVShareBind: msg.AcceptValidatedCredentialsVShareBind,
		SenderOptions:                        msg.AcceptCredentialType,
		RecoverShares:                        recoverShares,
	}

	c.ContextDebug(ctx, "wallet "+w.String())

	k.SetWallet(ctx, w)

	c.ContextDebug(ctx, "saved wallet")

	return &types.MsgCreateWalletResponse{}, nil
}
