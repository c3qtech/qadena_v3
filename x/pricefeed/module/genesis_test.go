package pricefeed_test

import (
	"testing"

	keepertest "github.com/c3qtech/qadena_v3/testutil/keeper"
	"github.com/c3qtech/qadena_v3/testutil/nullify"
	pricefeed "github.com/c3qtech/qadena_v3/x/pricefeed/module"
	"github.com/c3qtech/qadena_v3/x/pricefeed/types"

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
