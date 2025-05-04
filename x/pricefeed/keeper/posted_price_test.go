package keeper_test

import (
	"context"
	"strconv"
	"testing"

	keepertest "qadena_v3/testutil/keeper"
	"qadena_v3/testutil/nullify"
	"qadena_v3/x/pricefeed/keeper"
	"qadena_v3/x/pricefeed/types"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"
)

// Prevent strconv unused error
var _ = strconv.IntSize

func createNPostedPrice(keeper keeper.Keeper, ctx context.Context, n int) []types.PostedPrice {
	items := make([]types.PostedPrice, n)
	for i := range items {
		items[i].MarketId = strconv.Itoa(i)
		items[i].OracleAddress = sdk.AccAddress(strconv.Itoa(i))

		keeper.SetPostedPrice(ctx, items[i])
	}
	return items
}

func TestPostedPriceGet(t *testing.T) {
	keeper, ctx := keepertest.PricefeedKeeper(t)
	items := createNPostedPrice(keeper, ctx, 10)
	for _, item := range items {
		rst, found := keeper.GetPostedPrice(ctx,
			item.MarketId,
			item.OracleAddress,
		)
		require.True(t, found)
		require.Equal(t,
			nullify.Fill(&item),
			nullify.Fill(&rst),
		)
	}
}
func TestPostedPriceRemove(t *testing.T) {
	keeper, ctx := keepertest.PricefeedKeeper(t)
	items := createNPostedPrice(keeper, ctx, 10)
	for _, item := range items {
		keeper.RemovePostedPrice(ctx,
			item.MarketId,
			item.OracleAddress,
		)
		_, found := keeper.GetPostedPrice(ctx,
			item.MarketId,
			item.OracleAddress,
		)
		require.False(t, found)
	}
}

func TestPostedPriceGetAll(t *testing.T) {
	keeper, ctx := keepertest.PricefeedKeeper(t)
	items := createNPostedPrice(keeper, ctx, 10)
	require.ElementsMatch(t,
		nullify.Fill(items),
		nullify.Fill(keeper.GetAllPostedPrice(ctx)),
	)
}
