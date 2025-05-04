package keeper

import (
	"fmt"

	c "qadena/x/qadena/common"
	"qadena/x/qadena/types"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

func (k Keeper) getSSIntervalPubK(ctx sdk.Context) (string, string) {
	ssWalletIntervalPubKID, found := k.GetIntervalPublicKeyID(ctx, types.SSNodeID, types.SSNodeType)
	if found {
		c.ContextDebug(ctx, "ssWalletIntervalPubKID "+ssWalletIntervalPubKID.PubKID)
	} else {
		return "", ""
	}

	ssWalletIntervalPubK, found := k.GetPublicKey(ctx, ssWalletIntervalPubKID.PubKID, types.TransactionPubKType)
	if found {
		c.ContextDebug(ctx, "ssWalletIntervalPubK "+ssWalletIntervalPubK.PubK)
	} else {
		return "", ""
	}

	return ssWalletIntervalPubKID.PubKID, ssWalletIntervalPubK.PubK
}

func (k Keeper) getTreasuryPubKID(ctx sdk.Context) string {
	treasuryWalletIntervalPubKID, found := k.GetIntervalPublicKeyID(ctx, types.TreasuryNodeID, types.TreasuryNodeType)
	if found {
		c.ContextDebug(ctx, "treasuryWalletIntervalPubKID "+treasuryWalletIntervalPubKID.PubKID)
	} else {
		c.ContextError(ctx, "Couldn't find treasury pubkid "+types.ErrGenericTreasury.Error())
		panic(types.ErrGenericTreasury.Error())
	}

	return treasuryWalletIntervalPubKID.PubKID
}

func (k Keeper) getTreasuryAddress(ctx sdk.Context) (treasury sdk.AccAddress) {
	treasuryPubKID := k.getTreasuryPubKID(ctx)
	c.ContextDebug(ctx, "treasuryPubKID "+treasuryPubKID)
	treasuryAddress, err := sdk.AccAddressFromBech32(treasuryPubKID)

	if err != nil {
		c.ContextError(ctx, err.Error())
		panic(err.Error())
	}

	c.ContextDebug(ctx, "treasuryAddress "+treasuryAddress.String())
	return treasuryAddress
}

func (k Keeper) distributeIncentives(ctx sdk.Context, accountAddress sdk.AccAddress, coin sdk.Coin) (err error) {
	coin = sdk.NormalizeCoin(coin)
	c.ContextDebug(ctx, "distributeIncentives "+coin.String())

	err = k.bankKeeper.SendCoinsFromAccountToModule(ctx, k.getTreasuryAddress(ctx), types.ModuleName, sdk.NewCoins(coin))

	if err != nil {
		c.ContextError(ctx, "Temp transfer to module:  SendCoinsFromAccountToModule err "+err.Error())
		return err
	}

	err = k.bankKeeper.SendCoinsFromModuleToAccount(ctx, types.ModuleName, accountAddress, sdk.NewCoins(coin))

	if err != nil {
		c.ContextError(ctx, "Final transfer to accountAddress:  SendCoinsFromModuleToAccount err "+err.Error())
		return err
	}

	c.ContextDebug(ctx, "coins transferred to account address")

	return nil
}

func (k Keeper) lockAccountAmount(ctx sdk.Context, accountAddress sdk.AccAddress, coin sdk.Coin) (err error) {
	coin = sdk.NormalizeCoin(coin)
	c.ContextDebug(ctx, "lockAccountAmount "+coin.String())

	err = k.bankKeeper.SendCoinsFromAccountToModule(ctx, accountAddress, types.ModuleName, sdk.NewCoins(coin))

	if err != nil {
		c.ContextError(ctx, "Transfer to module:  SendCoinsFromAccountToModule err "+err.Error())
		return err
	}

	fmt.Println(coin, "coins transferred from address", accountAddress, "to module", types.ModuleName)

	return nil
}

func (k Keeper) unlockAccountAmount(ctx sdk.Context, accountAddress sdk.AccAddress, coin sdk.Coin) (err error) {
	coin = sdk.NormalizeCoin(coin)
	c.ContextDebug(ctx, "unlockAccountAmount "+coin.String())

	err = k.bankKeeper.SendCoinsFromModuleToAccount(ctx, types.ModuleName, accountAddress, sdk.NewCoins(coin))

	if err != nil {
		c.ContextError(ctx, "Transfer from module to address:  SendCoinsFromModuleToAccount err "+err.Error())
		return err
	}

	c.ContextDebug(ctx, coin.String()+" "+types.ModuleName+" to address "+accountAddress.String())

	return nil
}
