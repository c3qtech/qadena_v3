package keeper

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"qadena/x/qadena/types"

	c "qadena/x/qadena/common"

	"cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

func (k msgServer) CreateBulkCredentials(goCtx context.Context, msg *types.MsgCreateBulkCredentials) (*types.MsgCreateBulkCredentialsResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	unprotoCredentialInfoBindData := c.UnprotoizeVShareBindData(msg.CredentialInfoVShareBind)

	// this node can do the bind verification but needs to look-up the public keys used to ensure that the client isn't cheating that way; it's an additional step and left for a future update

	// check bind
	// compute hash of vshare encrypted data in bulkCredentials

	hash := sha256.New()
	for _, bulkCredential := range msg.BulkCredentials {
		hash.Write(bulkCredential.EncCredentialInfoVShare)
	}
	// get hash
	hashed := hash.Sum(nil)

	// print hashed
	fmt.Println("hashed", hex.EncodeToString(hashed))

	if unprotoCredentialInfoBindData.VShareBVerify(hashed) {
		fmt.Println("bind verified")
	} else {
		c.ContextDebug(ctx, "VShareBVerify failed")
		return nil, types.ErrVShareVerification
	}

	/*
		err := k.RegisterCreator(msg.Creator)
		if err != nil {
			c.ContextError(ctx, "error registering creator "+err.Error())
			return nil, err
		}
	*/

	for _, bulkCredential := range msg.BulkCredentials {

		_, found := k.GetCredential(ctx, bulkCredential.CredentialID, msg.CredentialType)

		if found {
			return nil, types.ErrCredentialExists
		}

		c.ContextDebug(ctx, "creating Credential")

		moduleParams := k.GetParams(ctx)

		createCredentialGas := moduleParams.GetCreateCredentialFee()

		// display module
		c.ContextDebug(ctx, "moduleParams "+moduleParams.String())

		c.ContextDebug(ctx, "createCredentialGas "+createCredentialGas)

		// convert to coin
		coin, err := sdk.ParseDecCoin(createCredentialGas)

		if err != nil {
			c.ContextError(ctx, "error parsing coin "+err.Error())
			return nil, err
		}

		// display coin
		c.ContextDebug(ctx, "createCredential gas fee "+coin.String())

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

			c.ContextDebug(ctx, "createCredential gas fee in "+types.QadenaTokenDenom+" "+price.String())

			coin, err = sdk.ParseDecCoin(price.String() + types.QadenaTokenDenom)
			if err != nil {
				c.ContextError(ctx, "error parsing coin "+err.Error())
				return nil, err
			}

			c.ContextDebug(ctx, "createCredential gas fee "+coin.String())
		}

		// is this a new one or a renewal?

		var royaltyToApp math.LegacyDec
		var royaltyToReference math.LegacyDec

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

		// calculate gas

		gas := coin.Amount.Sub(payToApp)

		gas = gas.Sub(payToReference)

		c.ContextDebug(ctx, "gas "+gas.String())

		gasCoin, err := sdk.ParseCoinNormalized(gas.String() + types.QadenaTokenDenom)

		if err != nil {
			c.ContextError(ctx, "error parsing gasCoin "+err.Error())
			return nil, err
		}

		// print gasCoin
		c.ContextDebug(ctx, "gasCoin "+gasCoin.String())

		// consume gas
		ctx.GasMeter().ConsumeGas(gasCoin.Amount.Uint64()/k.cachedGasPriceInAQDN.Get(), "createCredential")

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
		}

		c.ContextDebug(ctx, "credential "+cred.String())

		err = k.SetCredential(ctx, cred)
		if err != nil {
			c.ContextError(ctx, "error setting credential "+err.Error())
			return nil, err
		}
	}

	return &types.MsgCreateBulkCredentialsResponse{}, nil
}
