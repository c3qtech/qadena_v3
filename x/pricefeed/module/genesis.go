package pricefeed

import (
	sdk "github.com/cosmos/cosmos-sdk/types"

	"qadena_v3/x/pricefeed/keeper"
	"qadena_v3/x/pricefeed/types"
)

// InitGenesis initializes the module's state from a provided genesis state.
func InitGenesis(ctx sdk.Context, k keeper.Keeper, genState types.GenesisState) {
	// Set all the postedPrice
	for _, elem := range genState.PostedPriceList {
		if elem.Expiry.After(ctx.BlockTime()) {
			_, err := k.SetPrice(ctx, elem.OracleAddress, elem.MarketId, elem.Price, elem.Expiry)
			if err != nil {
				panic(err)
			}
		}
	}
	// this line is used by starport scaffolding # genesis/module/init
	if err := k.SetParams(ctx, genState.Params); err != nil {
		panic(err)
	}

	params := k.GetParams(ctx)

	// Set the current price (if any) based on what's now in the store
	for _, market := range params.Markets {
		if !market.Active {
			continue
		}
		rps := k.GetRawPrices(ctx, market.MarketId)

		if len(rps) == 0 {
			continue
		}
		err := k.SetCurrentPrices(ctx, market.MarketId)
		if err != nil {
			panic(err)
		}
	}

}

// ExportGenesis returns the module's exported genesis.
func ExportGenesis(ctx sdk.Context, k keeper.Keeper) *types.GenesisState {
	genesis := types.DefaultGenesis()
	genesis.Params = k.GetParams(ctx)

	genesis.PostedPriceList = k.GetAllPostedPrice(ctx)
	// this line is used by starport scaffolding # genesis/module/export

	return genesis
}
