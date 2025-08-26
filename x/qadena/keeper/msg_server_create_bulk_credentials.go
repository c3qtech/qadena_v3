package keeper

import (
	"context"
	"strconv"

	"github.com/c3qtech/qadena_v3/x/qadena/types"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"

	cosmosmath "cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

func (k msgServer) CreateBulkCredentials(goCtx context.Context, msg *types.MsgCreateBulkCredentials) (*types.MsgCreateBulkCredentialsResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	c.ContextDebug(ctx, "CreateBulkCredentials isCheckTx=", ctx.IsCheckTx())

	creatorAddress, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		c.ContextDebug(ctx, "CreateBulkCredentials Invalid creator "+msg.Creator)
		return nil, types.ErrInvalidCreator
	}

	// check if the creator is an identity service provider
	err = k.AuthenticateServiceProvider(ctx, msg.Creator, types.IdentityServiceProvider)
	if err != nil {
		return nil, err
	}

	ccPubK := make([]c.VSharePubKInfo, 0)

	ccPubK, err = MsgServerAppendRequiredChainCCPubK(ctx, ccPubK, k.Keeper, "", false)

	if err != nil {
		return nil, err
	}

	// validate credential info vshare
	var encVShare [][]byte

	for _, bulkCredential := range msg.BulkCredentials {
		encVShare = append(encVShare, bulkCredential.EncCredentialInfoVShare)
	}

	if !c.ValidateBulkVShare(ctx, msg.CredentialInfoVShareBind, encVShare, ccPubK) {
		return nil, types.ErrInvalidVShare
	}

	// validate credential hash vshare
	var encVShareHash [][]byte

	for _, bulkCredential := range msg.BulkCredentials {
		encVShareHash = append(encVShareHash, bulkCredential.EncCredentialHashVShare)
	}

	if !c.ValidateBulkVShare(ctx, msg.CredentialHashVShareBind, encVShareHash, ccPubK) {
		return nil, types.ErrInvalidVShare
	}

	moduleParams := k.GetParams(ctx)

	createCredentialFee := moduleParams.CreateBulkCredentialsFee

	// display module
	c.ContextDebug(ctx, "CreateBulkCredentials moduleParams "+moduleParams.String())

	c.ContextDebug(ctx, "CreateBulkCredentials createBulkCredentialFee "+createCredentialFee)

	// convert to createCredentialFeeCoin
	createCredentialFeeCoin, err := sdk.ParseDecCoin(createCredentialFee)

	if err != nil {
		c.ContextError(ctx, "error parsing coin "+err.Error())
		return nil, err
	}

	// display coin
	c.ContextDebug(ctx, "CreateBulkCredentials fee per credential "+createCredentialFeeCoin.String())

	// number of credentials
	numberOfCredentials := len(msg.BulkCredentials)

	// calculate total fee
	createCredentialFeeCoin.Amount = createCredentialFeeCoin.Amount.Mul(cosmosmath.LegacyNewDec(int64(numberOfCredentials)))

	// display coin
	c.ContextDebug(ctx, "CreateBulkCredentials fee total (numberOfCredentials="+strconv.Itoa(numberOfCredentials)+") "+createCredentialFeeCoin.String())

	// if coin is not AQadenaTokenDenom, then let's do conversions
	if !(createCredentialFeeCoin.Denom == types.AQadenaTokenDenom || createCredentialFeeCoin.Denom == types.QadenaTokenDenom) {
		// check pricefeed

		marketPrefix := "cn" // crypto == "cn", fiat == "fn"

		marketID := marketPrefix + ":" + types.QadenaTokenDenom + ":" + createCredentialFeeCoin.Denom
		cp, err := k.pricefeedKeeper.GetCurrentPrice(ctx, marketID)
		var basePrice cosmosmath.LegacyDec
		if err != nil {
			basePrice = cosmosmath.LegacyNewDecFromBigInt(c.BigIntZero)
		} else {
			basePrice = cp.Price
		}

		c.ContextDebug(ctx, types.QadenaTokenDenom+" to "+createCredentialFeeCoin.Denom+" base fee "+basePrice.String())

		price := createCredentialFeeCoin.Amount.Quo(basePrice)

		c.ContextDebug(ctx, "CreateBulkCredentials fee in "+types.QadenaTokenDenom+" "+price.String())

		createCredentialFeeCoin, err = sdk.ParseDecCoin(price.String() + types.QadenaTokenDenom)
		if err != nil {
			c.ContextError(ctx, "error parsing coin "+err.Error())
			return nil, err
		}

		c.ContextDebug(ctx, "CreateBulkCredentials fee "+createCredentialFeeCoin.String())
	}

	// check if we have enough funds to create credential

	// new credential flow

	var payToEKYCApp cosmosmath.LegacyDec = cosmosmath.LegacyNewDec(0)
	var payToReusedIdentityProvider cosmosmath.LegacyDec = cosmosmath.LegacyNewDec(0)
	var payToIdentityOwner cosmosmath.LegacyDec = cosmosmath.LegacyNewDec(0)

	if msg.EKYCAppWalletID != "" {
		// make sure this is a valid eKYCApp wallet
		eKYCAppAddress, err := sdk.AccAddressFromBech32(msg.EKYCAppWalletID)
		if err != nil {
			return nil, types.ErrInvalidEKYCAppWalletID
		}
		account := k.accountKeeper.GetAccount(ctx, eKYCAppAddress)
		if account == nil {
			return nil, types.ErrInvalidEKYCAppWalletID
		}

		// get the percentage for new app royalty
		eKycSubmitNewAppRoyaltyPercentage := moduleParams.GetEkycSubmitNewAppRoyaltyPercentage()

		// convert to Dec
		eKycSubmitNewAppRoyaltyPercentageDec, err := cosmosmath.LegacyNewDecFromStr(eKycSubmitNewAppRoyaltyPercentage)

		if err != nil {
			c.ContextError(ctx, "CreateBulkCredentials error parsing eKycSubmitNewAppRoyaltyPercentage "+err.Error())
			return nil, err
		}

		// divide by 100
		incentiveToEKYCApp := eKycSubmitNewAppRoyaltyPercentageDec.Quo(cosmosmath.LegacyNewDec(100))

		payToEKYCApp := createCredentialFeeCoin.Amount.Mul(incentiveToEKYCApp)

		c.ContextDebug(ctx, "CreateBulkCredentials payToEKYCApp "+payToEKYCApp.String())

		payToEKYCAppCoin, err := sdk.ParseCoinNormalized(payToEKYCApp.String() + types.QadenaTokenDenom)

		if err != nil {
			c.ContextError(ctx, "CreateBulkCredentials error parsing payToAppCoin "+err.Error())
			return nil, err
		}

		// print payToAppCoin
		c.ContextDebug(ctx, "CreateBulkCredentials payToEKYCAppCoin "+payToEKYCAppCoin.String())

		// we need to incentivize the EKYCAppWalletID

		// transfer to module account
		err = k.bankKeeper.SendCoinsFromAccountToModule(ctx, creatorAddress, types.ModuleName, sdk.NewCoins(payToEKYCAppCoin))

		if err != nil {
			c.ContextError(ctx, "CreateBulkCredentials error sending coins to module account "+err.Error())
			return nil, err
		}

		// transfer to app address
		err = k.bankKeeper.SendCoinsFromModuleToAccount(ctx, types.ModuleName, eKYCAppAddress, sdk.NewCoins(payToEKYCAppCoin))

		if err != nil {
			c.ContextError(ctx, "CreateBulkCredentials error sending coins to app account "+err.Error())
			return nil, err
		}

	}

	// calculate gas

	gasFee := createCredentialFeeCoin.Amount.Sub(payToEKYCApp)

	gasFee = gasFee.Sub(payToReusedIdentityProvider)

	gasFee = gasFee.Sub(payToIdentityOwner)

	c.ContextDebug(ctx, "CreateBulkCredentials gas fee after paying incentives", gasFee.String())

	// convert fee to gas based on gas price
	gas := gasFee.Quo(c.GasPriceInAQDN)

	gasAsCoin, err := sdk.ParseCoinNormalized(gas.String() + types.QadenaTokenDenom)

	if err != nil {
		c.ContextError(ctx, "CreateBulkCredentials error parsing gasAsCoin", err.Error())
		return nil, err
	}

	// print gasCoin
	c.ContextDebug(ctx, "CreateBulkCredentials gas after paying incentives", gasAsCoin.String())

	var gasAsUint64 uint64

	if gasAsCoin.Amount.IsInt64() {
		gasAsUint64 = gasAsCoin.Amount.Uint64()
	} else {
		gasAsUint64 = ctx.GasMeter().Limit()
	}

	ctx.GasMeter().ConsumeGas(gasAsUint64, "CreateBulkCredentials")

	for _, bulkCredential := range msg.BulkCredentials {

		_, found := k.GetCredential(ctx, bulkCredential.CredentialID, msg.CredentialType)

		if found {
			return nil, types.ErrCredentialExists
		}

		c.ContextDebug(ctx, "CreateBulkCredentials Creating Credential")

		cred := types.Credential{
			CredentialID:                 bulkCredential.CredentialID,
			CredentialType:               msg.CredentialType,
			WalletID:                     "",
			CredentialPedersenCommit:     bulkCredential.CredentialPedersenCommit,
			EncCredentialHashVShare:      bulkCredential.EncCredentialHashVShare,
			CredentialHashVShareBind:     msg.CredentialHashVShareBind,
			EncCredentialInfoVShare:      bulkCredential.EncCredentialInfoVShare,
			CredentialInfoVShareBind:     msg.CredentialInfoVShareBind,
			FindCredentialPedersenCommit: bulkCredential.FindCredentialPedersenCommit,
			ReferenceCredentialID:        "",
			ProviderWalletID:             msg.Creator,
			IdentityOwnerWalletID:        "",
			EkycAppWalletID:              msg.EKYCAppWalletID,
		}

		c.ContextDebug(ctx, "CreateBulkCredentials credential "+cred.String())

		err = k.SetCredential(ctx, cred)
		if err != nil {
			c.ContextError(ctx, "CreateBulkCredentials error setting credential "+err.Error())
			return nil, err
		}
	}

	return &types.MsgCreateBulkCredentialsResponse{}, nil
}
