package pricefeed_test

import (
	"testing"

	keepertest "qadena_v3/testutil/keeper"
	"qadena_v3/testutil/nullify"
	pricefeed "qadena_v3/x/pricefeed/module"
	"qadena_v3/x/pricefeed/types"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"
)

func TestGenesis(t *testing.T) {
	genesisState := types.GenesisState{
		Params: types.DefaultParams(),

		PostedPriceList: []types.PostedPrice{
			{
				MarketId:      "0",
				OracleAddress: sdk.AccAddress("0"),
			},
			{
				MarketId:      "1",
				OracleAddress: sdk.AccAddress("1"),
			},
		},
		// this line is used by starport scaffolding # genesis/test/state
	}

	k, ctx := keepertest.PricefeedKeeper(t)
	pricefeed.InitGenesis(ctx, k, genesisState)
	got := pricefeed.ExportGenesis(ctx, k)
	require.NotNil(t, got)

	nullify.Fill(&genesisState)
	nullify.Fill(got)

	require.ElementsMatch(t, genesisState.PostedPriceList, got.PostedPriceList)
	// this line is used by starport scaffolding # genesis/test/assert
}
