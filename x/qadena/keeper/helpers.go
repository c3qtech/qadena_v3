package keeper

import (
	c "github.com/c3qtech/qadena_v3/x/qadena/common"
	"github.com/c3qtech/qadena_v3/x/qadena/types"

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

// getIncentivePoolPubKID returns the PubKID of the account that funds create_wallet incentives.
// The PubKID IS the bech32 address (see getIncentivePoolAddress).  Genesis must carry an
// intervalPublicKeyIDList entry with nodeID and nodeType both "incentive-pool", or every wallet
// creation PANICS here.
func (k Keeper) getIncentivePoolPubKID(ctx sdk.Context) string {
	incentivePoolIntervalPubKID, found := k.GetIntervalPublicKeyID(ctx, types.IncentivePoolNodeID, types.IncentivePoolNodeType)
	if found {
		c.ContextDebug(ctx, "incentivePoolIntervalPubKID "+incentivePoolIntervalPubKID.PubKID)
	} else {
		c.ContextError(ctx, "Couldn't find incentive-pool pubkid "+types.ErrGenericIncentivePool.Error())
		panic(types.ErrGenericIncentivePool.Error())
	}

	return incentivePoolIntervalPubKID.PubKID
}

func (k Keeper) getIncentivePoolAddress(ctx sdk.Context) (incentivePool sdk.AccAddress) {
	incentivePoolPubKID := k.getIncentivePoolPubKID(ctx)
	c.ContextDebug(ctx, "incentivePoolPubKID "+incentivePoolPubKID)
	incentivePoolAddress, err := sdk.AccAddressFromBech32(incentivePoolPubKID)

	if err != nil {
		c.ContextError(ctx, err.Error())
		panic(err.Error())
	}

	c.ContextDebug(ctx, "incentivePoolAddress "+incentivePoolAddress.String())
	return incentivePoolAddress
}

func (k Keeper) distributeIncentives(ctx sdk.Context, accountAddress sdk.AccAddress, coin sdk.Coin) (err error) {
	coin = sdk.NormalizeCoin(coin)
	c.ContextDebug(ctx, "distributeIncentives "+coin.String())

	err = k.bankKeeper.SendCoinsFromAccountToModule(ctx, k.getIncentivePoolAddress(ctx), types.ModuleName, sdk.NewCoins(coin))

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

	c.ContextDebug(ctx, coin.String()+" coins transferred from address "+accountAddress.String()+" to module "+types.ModuleName)

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
