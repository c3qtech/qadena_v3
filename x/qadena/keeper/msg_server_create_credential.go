package keeper

import (
	"context"

	"github.com/c3qtech/qadena_v3/x/qadena/types"

	sdk "github.com/cosmos/cosmos-sdk/types"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"

	"cosmossdk.io/math"
)

// AUTHORIZATION:
//
//	make sure that the creator *IS* an identity service provider
//	make sure that all the required signatory vshares ccPubK has ss interval public key
func (k msgServer) CreateCredential(goCtx context.Context, msg *types.MsgCreateCredential) (*types.MsgCreateCredentialResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	c.ContextDebug(ctx, "create credential isCheckTx=", ctx.IsCheckTx())

	creatorIntervalPubKID, found := k.GetIntervalPublicKeyIDByPubKID(ctx, msg.Creator)

	if !found {
		return nil, types.ErrServiceProviderUnauthorized
	}

	if creatorIntervalPubKID.GetServiceProviderType() != types.IdentityServiceProvider {
		return nil, types.ErrServiceProviderUnauthorized
	}

	ccPubK := make([]c.VSharePubKInfo, 0)

	ccPubK, err := MsgServerAppendRequiredChainCCPubK(ctx, ccPubK, k.Keeper, "", false)

	if err != nil {
		return nil, err
	}

	/*
		err = k.RegisterCreator(msg.Creator)
		if err != nil {
			c.ContextError(ctx, "error registering creator "+err.Error())
			return nil, err
		}
	*/

	if !c.ValidateVShare(ctx, msg.CredentialInfoVShareBind, msg.EncCredentialInfoVShare, ccPubK) {
		return nil, types.ErrInvalidVShare
	}

	_, found = k.GetCredential(ctx, msg.CredentialID, msg.CredentialType)

	if found {
		return nil, types.ErrCredentialExists
	}

	c.ContextDebug(ctx, "creating Credential")

	moduleParams := k.GetParams(ctx)

	createCredentialFee := moduleParams.GetCreateCredentialFee()

	// display module
	c.ContextDebug(ctx, "moduleParams "+moduleParams.String())

	c.ContextDebug(ctx, "createCredentialFee "+createCredentialFee)

	// convert to coin
	coin, err := sdk.ParseDecCoin(createCredentialFee)

	if err != nil {
		c.ContextError(ctx, "error parsing coin "+err.Error())
		return nil, err
	}

	// display coin
	c.ContextDebug(ctx, "createCredential fee "+coin.String())

	// if coin is not AQadenaTokenDenom, then let's do conversions
	if !(coin.Denom == types.AQadenaTokenDenom || coin.Denom == types.QadenaTokenDenom) {
		// check pricefeed

		marketPrefix := "cn"

		marketID := marketPrefix + ":" + types.QadenaTokenDenom + ":" + coin.Denom
		cp, err := k.pricefeedKeeper.GetCurrentPrice(ctx, marketID)
		var basePrice math.LegacyDec
		if err != nil {
			basePrice = math.LegacyNewDecFromBigInt(c.BigIntZero)
		} else {
			basePrice = cp.Price
		}

		c.ContextDebug(ctx, types.QadenaTokenDenom+" to "+coin.Denom+" base fee "+basePrice.String())

		price := coin.Amount.Quo(basePrice)

		c.ContextDebug(ctx, "createCredential fee in "+types.QadenaTokenDenom+" "+price.String())

		coin, err = sdk.ParseDecCoin(price.String() + types.QadenaTokenDenom)
		if err != nil {
			c.ContextError(ctx, "error parsing coin "+err.Error())
			return nil, err
		}

		c.ContextDebug(ctx, "createCredential fee "+coin.String())
		normCoin := sdk.NormalizeDecCoin(coin)
		c.ContextDebug(ctx, "createCredential fee equivalent "+normCoin.String())
	}

	// is this a new one or a renewal?

	var royaltyToApp math.LegacyDec
	var royaltyToReference math.LegacyDec

	if msg.ReferenceCredentialID == "" {
		// new credential

		// check if we have enough funds to create credential

		// get the percentage for new app royalty
		eKycSubmitNewAppRoyaltyPercentage := moduleParams.GetEkycSubmitNewAppRoyaltyPercentage()

		// convert to Dec
		eKycSubmitNewAppRoyaltyPercentageDec, err := math.LegacyNewDecFromStr(eKycSubmitNewAppRoyaltyPercentage)

		if err != nil {
			c.ContextError(ctx, "error parsing eKycSubmitNewAppRoyaltyPercentage "+err.Error())
			return nil, err
		}

		// divide by 100
		royaltyToApp = eKycSubmitNewAppRoyaltyPercentageDec.Quo(math.LegacyNewDec(100))
		royaltyToReference = math.LegacyNewDec(0)
	} else {
		// renewal

		// get the percentage for new app royalty
		eKycSubmitReuseAppRoyaltyPercentage := moduleParams.GetEkycSubmitReuseAppRoyaltyPercentage()

		// convert to Dec
		eKycSubmitReuseAppRoyaltyPercentageDec, err := math.LegacyNewDecFromStr(eKycSubmitReuseAppRoyaltyPercentage)

		if err != nil {
			c.ContextError(ctx, "error parsing eKycSubmitReuseAppRoyaltyPercentage "+err.Error())
			return nil, err
		}

		// divide by 100
		royaltyToApp = eKycSubmitReuseAppRoyaltyPercentageDec.Quo(math.LegacyNewDec(100))

		// get the percentage for new provider
		eKycSubmitReuseProviderRoyaltyPercentage := moduleParams.GetEkycSubmitReuseProviderRoyaltyPercentage()

		// conver to Dec
		eKycSubmitReuseProviderRoyaltyPercentageDec, err := math.LegacyNewDecFromStr(eKycSubmitReuseProviderRoyaltyPercentage)

		if err != nil {
			c.ContextError(ctx, "error parsing eKycSubmitReuseProviderRoyaltyPercentage "+err.Error())
			return nil, err
		}

		// divide by 100
		royaltyToReference = eKycSubmitReuseProviderRoyaltyPercentageDec.Quo(math.LegacyNewDec(100))

	}

	// calcaulate royalty to app
	payToApp := coin.Amount.Mul(royaltyToApp)

	c.ContextDebug(ctx, "payToApp "+payToApp.String())

	payToAppCoin, err := sdk.ParseCoinNormalized(payToApp.String() + types.QadenaTokenDenom)

	if err != nil {
		c.ContextError(ctx, "error parsing payToAppCoin "+err.Error())
		return nil, err
	}

	// print payToAppCoin
	c.ContextDebug(ctx, "payToAppCoin "+payToAppCoin.String())

	// calculate royalty to reference
	payToReference := coin.Amount.Mul(royaltyToReference)

	c.ContextDebug(ctx, "payToReference "+payToReference.String())

	payToReferenceCoin, err := sdk.ParseCoinNormalized(payToReference.String() + types.QadenaTokenDenom)

	if err != nil {
		c.ContextError(ctx, "error parsing payToReferenceCoin "+err.Error())
		return nil, err
	}

	// calculate gas

	gas := coin.Amount.Sub(payToApp)

	gas = gas.Sub(payToReference)

	c.ContextDebug(ctx, "gas "+gas.String())

	gasCoin, err := sdk.ParseCoinNormalized(gas.String() + types.QadenaTokenDenom)

	if err != nil {
		c.ContextError(ctx, "error parsing gasCoin", err.Error())
		return nil, err
	}

	// print gasCoin
	c.ContextDebug(ctx, "gas fee after paying royalties", gasCoin.String())

	// consume gas
	consume := gasCoin.Amount.Uint64() / c.GasPrice

	c.ContextDebug(ctx, "will consume gas", consume)

	ctx.GasMeter().ConsumeGas(consume, "createCredential")

	creatorAddress, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		c.ContextDebug(ctx, "Invalid creator "+msg.Creator)
		return nil, types.ErrInvalidCreator
	}

	if msg.EKYCAppWalletID != "" {
		// we need to incentivize the EKYCAppWalletID

		// transfer to module account
		err = k.bankKeeper.SendCoinsFromAccountToModule(ctx, creatorAddress, types.ModuleName, sdk.NewCoins(payToAppCoin))

		if err != nil {
			c.ContextError(ctx, "error sending coins to module account "+err.Error())
			return nil, err
		}

		appAddress, err := sdk.AccAddressFromBech32(msg.EKYCAppWalletID)

		if err != nil {
			c.ContextDebug(ctx, "Invalid EKYCAppWalletID "+msg.EKYCAppWalletID)
			return nil, types.ErrInvalidEKYCAppWalletID
		}

		// transfer to app address
		err = k.bankKeeper.SendCoinsFromModuleToAccount(ctx, types.ModuleName, appAddress, sdk.NewCoins(payToAppCoin))

		if err != nil {
			c.ContextError(ctx, "error sending coins to app account "+err.Error())
			return nil, err
		}
	}

	if msg.ReferenceCredentialID != "" {
		// we need to incentivize the reference
		// pay to reference
		// get credential
		cred, found := k.GetCredential(ctx, msg.ReferenceCredentialID, types.PersonalInfoCredentialType)

		if !found {
			c.ContextError(ctx, "error getting credential "+msg.ReferenceCredentialID)
			return nil, types.ErrCredentialNotExists
		}

		// display cred
		c.ContextDebug(ctx, "cred "+cred.String())

		// transfer to module account
		err = k.bankKeeper.SendCoinsFromAccountToModule(ctx, creatorAddress, types.ModuleName, sdk.NewCoins(payToReferenceCoin))

		if err != nil {
			c.ContextError(ctx, "error sending coins to module account "+err.Error())
			return nil, err
		}

		providerAddress, err := sdk.AccAddressFromBech32(cred.ProviderWalletID)

		if err != nil {
			c.ContextDebug(ctx, "Invalid ProviderWalletID "+cred.ProviderWalletID)
			return nil, types.ErrInvalidEKYCProviderWalletID
		}

		// transfer to app address
		err = k.bankKeeper.SendCoinsFromModuleToAccount(ctx, types.ModuleName, providerAddress, sdk.NewCoins(payToReferenceCoin))

		if err != nil {
			c.ContextError(ctx, "error sending coins to app account "+err.Error())
			return nil, err
		}

	}

	cred := types.Credential{
		CredentialID:                 msg.CredentialID,
		CredentialType:               msg.CredentialType,
		WalletID:                     "",
		CredentialPedersenCommit:     msg.CredentialPedersenCommit,
		EncCredentialHashVShare:      nil,
		CredentialHashVShareBind:     nil,
		EncCredentialInfoVShare:      msg.EncCredentialInfoVShare,
		CredentialInfoVShareBind:     msg.CredentialInfoVShareBind,
		FindCredentialPedersenCommit: msg.FindCredentialPedersenCommit,
		ReferenceCredentialID:        msg.ReferenceCredentialID,
		ProviderWalletID:             msg.Creator,
	}

	c.ContextDebug(ctx, "credential "+cred.String())

	err = k.SetCredential(ctx, cred)
	if err != nil {
		c.ContextError(ctx, "error setting credential "+err.Error())
		return nil, err
	}

	return &types.MsgCreateCredentialResponse{}, nil
}
