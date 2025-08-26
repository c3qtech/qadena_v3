package keeper

import (
	"context"

	"github.com/c3qtech/qadena_v3/x/qadena/types"

	sdk "github.com/cosmos/cosmos-sdk/types"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"

	cosmosmath "cosmossdk.io/math"
)

// AUTHORIZATION:
//
//	make sure that the creator *IS* an identity service provider
//	make sure that all the required signatory vshares ccPubK has ss interval public key
func (k msgServer) CreateCredential(goCtx context.Context, msg *types.MsgCreateCredential) (*types.MsgCreateCredentialResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	c.ContextDebug(ctx, "CreateCredential isCheckTx=", ctx.IsCheckTx())

	creatorAddress, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		c.ContextDebug(ctx, "Invalid creator "+msg.Creator)
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

	if !c.ValidateVShare(ctx, msg.CredentialInfoVShareBind, msg.EncCredentialInfoVShare, ccPubK) {
		return nil, types.ErrInvalidVShare
	}

	_, found := k.GetCredential(ctx, msg.CredentialID, msg.CredentialType)

	if found {
		return nil, types.ErrCredentialExists
	}

	c.ContextDebug(ctx, "CreateCredential Creating Credential")

	moduleParams := k.GetParams(ctx)

	createCredentialFee := moduleParams.GetCreateCredentialFee()

	// display module
	c.ContextDebug(ctx, "moduleParams "+moduleParams.String())

	c.ContextDebug(ctx, "createCredentialFee "+createCredentialFee)

	// convert to createCredentialFeeCoin
	createCredentialFeeCoin, err := sdk.ParseDecCoin(createCredentialFee)

	if err != nil {
		c.ContextError(ctx, "error parsing coin "+err.Error())
		return nil, err
	}

	// display coin
	c.ContextDebug(ctx, "createCredential fee "+createCredentialFeeCoin.String())

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

		c.ContextDebug(ctx, "createCredential fee in "+types.QadenaTokenDenom+" "+price.String())

		createCredentialFeeCoin, err = sdk.ParseDecCoin(price.String() + types.QadenaTokenDenom)
		if err != nil {
			c.ContextError(ctx, "error parsing coin "+err.Error())
			return nil, err
		}

		c.ContextDebug(ctx, "createCredential fee "+createCredentialFeeCoin.String())
		//		normCoin := sdk.NormalizeDecCoin(createCredentialFeeCoin)
		//		c.ContextDebug(ctx, "createCredential fee equivalent "+normCoin.String())
	}

	// is this a new one or a reuse?

	var incentiveToEKYCApp cosmosmath.LegacyDec
	var incentiveToSharingIdentityProvider cosmosmath.LegacyDec
	var incentiveToIdentityOwner cosmosmath.LegacyDec
	var reusedCredential types.Credential
	var ekycAppCredential types.Credential

	var eKYCAppWalletID string // if this is set, we need to process it as an eKYCApp
	var identityOwnerWalletID string

	if msg.ReferenceCredentialID == "" {
		// NEW CREDENTIAL FLOW

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
			eKYCAppWalletID = msg.EKYCAppWalletID // set eKYCAppWalletID if this was created by the eKYCApp
		}

		if msg.IdentityOwnerWalletID != "" {
			// make sure this is a valid identity owner wallet
			identityOwnerAddress, err := sdk.AccAddressFromBech32(msg.IdentityOwnerWalletID)
			if err != nil {
				return nil, types.ErrInvalidIdentityOwnerWalletID
			}
			account := k.accountKeeper.GetAccount(ctx, identityOwnerAddress)
			if account == nil {
				return nil, types.ErrInvalidIdentityOwnerWalletID
			}
			identityOwnerWalletID = msg.IdentityOwnerWalletID
		}

		// get the percentage for new app royalty
		eKycSubmitNewAppRoyaltyPercentage := moduleParams.GetEkycSubmitNewAppRoyaltyPercentage()

		// convert to Dec
		eKycSubmitNewAppRoyaltyPercentageDec, err := cosmosmath.LegacyNewDecFromStr(eKycSubmitNewAppRoyaltyPercentage)

		if err != nil {
			c.ContextError(ctx, "error parsing eKycSubmitNewAppRoyaltyPercentage "+err.Error())
			return nil, err
		}

		// divide by 100
		incentiveToEKYCApp = eKycSubmitNewAppRoyaltyPercentageDec.Quo(cosmosmath.LegacyNewDec(100))

		// there is no sharing identity provider for a new credential, so set to 0
		incentiveToSharingIdentityProvider = cosmosmath.LegacyNewDec(0)
	} else {
		if msg.EKYCAppWalletID != "" {
			// not allowed, eKYCAppWalletID can only be set for new credentials
			c.ContextError(ctx, "Cannot set EKYCAppWalletID when reusing credential")
			return nil, types.ErrInvalidEKYCAppWalletID
		}

		if msg.IdentityOwnerWalletID != "" {
			// not allowed, identityOwnerWalletID can only be set for new credentials
			c.ContextError(ctx, "Cannot set IdentityOwnerWalletID when reusing credential")
			return nil, types.ErrInvalidIdentityOwnerWalletID
		}

		// REUSE CREDENTIAL FLOW

		// first, get credential that this is reusing
		reusedCredential, found = k.GetCredential(ctx, msg.ReferenceCredentialID, types.PersonalInfoCredentialType)

		if !found {
			c.ContextError(ctx, "error getting reused credential "+msg.ReferenceCredentialID)
			return nil, types.ErrCredentialNotExists
		}

		// TODO, we need to check if this is a valid reuse, possibly by comparing the reused credential with the new credential (somehow)

		// display cred
		c.ContextDebug(ctx, "reusedCredential "+reusedCredential.String())

		// get the root credential

		// we need to find the "root" credential by going up the chain of ReferenceCredentialID until we find one that has an empty ReferenceCredentialID
		ekycAppCredential = reusedCredential
		for ekycAppCredential.ReferenceCredentialID != "" {
			ekycAppCredential, found = k.GetCredential(ctx, ekycAppCredential.ReferenceCredentialID, types.PersonalInfoCredentialType)
			if !found {
				c.ContextError(ctx, "error getting credential "+ekycAppCredential.ReferenceCredentialID)
				return nil, types.ErrCredentialNotExists
			}

			if ekycAppCredential.EkycAppWalletID == "" {
				c.ContextError(ctx, "ekycAppCredential.EkycAppWalletID is empty")
				return nil, types.ErrInvalidEKYCAppWalletID
			}
		}

		// log ekycAppCredential
		c.ContextDebug(ctx, "ekycAppCredential "+ekycAppCredential.String())
		eKYCAppWalletID = ekycAppCredential.EkycAppWalletID             // set eKYCAppWalletID
		identityOwnerWalletID = ekycAppCredential.IdentityOwnerWalletID // set identityOwnerWalletID

		// get the percentage for reuse app royalty
		eKycSubmitReuseAppRoyaltyPercentage := moduleParams.GetEkycSubmitReuseAppRoyaltyPercentage()

		// convert to Dec
		eKycSubmitReuseAppRoyaltyPercentageDec, err := cosmosmath.LegacyNewDecFromStr(eKycSubmitReuseAppRoyaltyPercentage)

		if err != nil {
			c.ContextError(ctx, "error parsing eKycSubmitReuseAppRoyaltyPercentage "+err.Error())
			return nil, err
		}

		// divide by 100
		incentiveToEKYCApp = eKycSubmitReuseAppRoyaltyPercentageDec.Quo(cosmosmath.LegacyNewDec(100))

		// get the percentage for new provider
		eKycSubmitReuseProviderRoyaltyPercentage := moduleParams.GetEkycSubmitReuseProviderRoyaltyPercentage()

		// convert to Dec
		eKycSubmitReuseProviderRoyaltyPercentageDec, err := cosmosmath.LegacyNewDecFromStr(eKycSubmitReuseProviderRoyaltyPercentage)

		if err != nil {
			c.ContextError(ctx, "error parsing eKycSubmitReuseProviderRoyaltyPercentage "+err.Error())
			return nil, err
		}

		// divide by 100
		incentiveToSharingIdentityProvider = eKycSubmitReuseProviderRoyaltyPercentageDec.Quo(cosmosmath.LegacyNewDec(100))

	}

	var payToEKYCApp cosmosmath.LegacyDec = cosmosmath.LegacyNewDec(0)
	var payToReusedIdentityProvider cosmosmath.LegacyDec = cosmosmath.LegacyNewDec(0)
	var payToIdentityOwner cosmosmath.LegacyDec = cosmosmath.LegacyNewDec(0)

	if eKYCAppWalletID != "" {
		// this credential is an eKYCApp credential

		// we need to incentivize the EKYCApp and the identity provider that is sharing this credential and the identity owner

		if identityOwnerWalletID != "" {
			// get the percentage for identity owner's incentive
			eKycIdentityOwnerIncentivePercentage := moduleParams.EkycIdentityOwnerRoyaltyPercentage

			// convert to Dec
			eKycIdentityOwnerRoyaltyPercentageDec, err := cosmosmath.LegacyNewDecFromStr(eKycIdentityOwnerIncentivePercentage)

			if err != nil {
				c.ContextError(ctx, "error parsing eKycIdentityOwnerRoyaltyPercentage "+err.Error())
				return nil, err
			}

			// divide by 100
			incentiveToIdentityOwner = eKycIdentityOwnerRoyaltyPercentageDec.Quo(cosmosmath.LegacyNewDec(100))

			payToIdentityOwner = createCredentialFeeCoin.Amount.Mul(incentiveToIdentityOwner)
		}

		c.ContextDebug(ctx, "payToIdentityOwner "+payToIdentityOwner.String())

		// calcaulate incentive to eKYC app
		payToEKYCApp = createCredentialFeeCoin.Amount.Mul(incentiveToEKYCApp)

		c.ContextDebug(ctx, "payToEKCYApp "+payToEKYCApp.String())

		if reusedCredential.CredentialID != "" {
			// calculate incentive to reference
			payToReusedIdentityProvider = createCredentialFeeCoin.Amount.Mul(incentiveToSharingIdentityProvider)

			c.ContextDebug(ctx, "payToReference "+payToReusedIdentityProvider.String())

		}

		// compute total incentives
		totalIncentives := payToEKYCApp.Add(payToReusedIdentityProvider).Add(payToIdentityOwner)

		totalIncentivesCoin, err := sdk.ParseCoinNormalized(totalIncentives.String() + types.QadenaTokenDenom)

		if err != nil {
			c.ContextError(ctx, "error parsing totalIncentivesCoin "+err.Error())
			return nil, err
		}

		// transfer the total to module account
		err = k.bankKeeper.SendCoinsFromAccountToModule(ctx, creatorAddress, types.ModuleName, sdk.NewCoins(totalIncentivesCoin))

		if err != nil {
			c.ContextError(ctx, "error sending total incentives to module account "+err.Error())
			return nil, err
		}

		eKYCAppAddress, err := sdk.AccAddressFromBech32(eKYCAppWalletID)

		if err != nil {
			c.ContextDebug(ctx, "Invalid EKYCAppWalletID "+eKYCAppWalletID)
			return nil, types.ErrInvalidEKYCAppWalletID
		}

		payToEKYCAppCoin, err := sdk.ParseCoinNormalized(payToEKYCApp.String() + types.QadenaTokenDenom)

		if err != nil {
			c.ContextError(ctx, "error parsing payToAppCoin "+err.Error())
			return nil, err
		}

		// log payToAppCoin
		c.ContextDebug(ctx, "payToEKYCAppCoin "+payToEKYCAppCoin.String())

		// transfer to eKYC app address
		err = k.bankKeeper.SendCoinsFromModuleToAccount(ctx, types.ModuleName, eKYCAppAddress, sdk.NewCoins(payToEKYCAppCoin))

		if err != nil {
			c.ContextError(ctx, "error sending coins to app account "+err.Error())
			return nil, err
		}

		if !payToIdentityOwner.IsZero() {
			identityOwnerAddress, err := sdk.AccAddressFromBech32(identityOwnerWalletID)

			if err != nil {
				c.ContextDebug(ctx, "Invalid IdentityOwnerWalletID "+identityOwnerWalletID)
				return nil, types.ErrInvalidIdentityOwnerWalletID
			}

			payToIdentityOwnerCoin, err := sdk.ParseCoinNormalized(payToIdentityOwner.String() + types.QadenaTokenDenom)

			if err != nil {
				c.ContextError(ctx, "error parsing payToIdentityOwnerCoin "+err.Error())
				return nil, err
			}

			// transfer to identity owner address
			err = k.bankKeeper.SendCoinsFromModuleToAccount(ctx, types.ModuleName, identityOwnerAddress, sdk.NewCoins(payToIdentityOwnerCoin))

			if err != nil {
				c.ContextError(ctx, "error sending coins to identity owner account "+err.Error())
				return nil, err
			}

		}

		if !payToReusedIdentityProvider.IsZero() {
			providerAddress, err := sdk.AccAddressFromBech32(reusedCredential.ProviderWalletID)

			if err != nil {
				c.ContextDebug(ctx, "Invalid ProviderWalletID "+reusedCredential.ProviderWalletID)
				return nil, types.ErrInvalidEKYCProviderWalletID
			}

			payToReferenceCoin, err := sdk.ParseCoinNormalized(payToReusedIdentityProvider.String() + types.QadenaTokenDenom)

			if err != nil {
				c.ContextError(ctx, "error parsing payToReferenceCoin "+err.Error())
				return nil, err
			}

			// transfer to app address
			err = k.bankKeeper.SendCoinsFromModuleToAccount(ctx, types.ModuleName, providerAddress, sdk.NewCoins(payToReferenceCoin))

			if err != nil {
				c.ContextError(ctx, "error sending coins to app account "+err.Error())
				return nil, err
			}

			// we need to incentivize the identity owner
		}
	}

	// calculate gas

	gasFee := createCredentialFeeCoin.Amount.Sub(payToEKYCApp)

	gasFee = gasFee.Sub(payToReusedIdentityProvider)

	gasFee = gasFee.Sub(payToIdentityOwner)

	c.ContextDebug(ctx, "gas fee after paying incentives", gasFee.String())

	// convert fee to gas based on gas price
	gas := gasFee.Quo(c.GasPriceInAQDN)

	gasAsCoin, err := sdk.ParseCoinNormalized(gas.String() + types.QadenaTokenDenom)

	if err != nil {
		c.ContextError(ctx, "error parsing gasAsCoin", err.Error())
		return nil, err
	}

	// print gasCoin
	c.ContextDebug(ctx, "gas after paying incentives", gasAsCoin.String())

	var gasAsUint64 uint64

	if gasAsCoin.Amount.IsInt64() {
		gasAsUint64 = gasAsCoin.Amount.Uint64()
	} else {
		gasAsUint64 = ctx.GasMeter().Limit()
	}

	ctx.GasMeter().ConsumeGas(gasAsUint64, "createCredential")

	newCredential := types.Credential{
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
		IdentityOwnerWalletID:        msg.IdentityOwnerWalletID,
		EkycAppWalletID:              msg.EKYCAppWalletID,
	}

	c.ContextDebug(ctx, "newCredential "+newCredential.String())

	err = k.SetCredential(ctx, newCredential)
	if err != nil {
		c.ContextError(ctx, "error setting credential "+err.Error())
		return nil, err
	}

	return &types.MsgCreateCredentialResponse{}, nil
}
