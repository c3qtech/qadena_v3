package keeper_test

import (
	"testing"
	"time"

	keepertest "github.com/c3qtech/qadena_v3/testutil/keeper"
	"github.com/c3qtech/qadena_v3/x/pricefeed/types"

	"cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"
)

// GetRawPrices must return only the prices posted for the market it was asked about.
//
// It used to return every posted price on the chain, because IterateRawPricesByMarket accepted a
// marketId and then iterated the whole PostedPrice keyspace with an empty prefix.  That fed
// SetCurrentPrices the union of all markets, so every market ended up storing the median across all
// of them -- e.g. a btc/usd market resolving to a sub-dollar figure taken from a fiat pair.
func TestGetRawPricesReturnsOnlyThatMarket(t *testing.T) {
	k, ctx := keepertest.PricefeedKeeper(t)
	sdkctx := sdk.UnwrapSDKContext(ctx)

	oracle := sdk.AccAddress("oracle")
	expiry := sdkctx.BlockTime().Add(24 * time.Hour)

	posted := []struct {
		marketID string
		price    string
	}{
		{"cn:btc:usd", "64363.66"},
		{"fn:php:usd", "0.016297"},
		{"cn:qdn:php", "0.613610"},
	}
	for _, p := range posted {
		k.SetPostedPrice(ctx, types.PostedPrice{
			MarketId:      p.marketID,
			OracleAddress: oracle,
			Price:         math.LegacyMustNewDecFromStr(p.price),
			Expiry:        expiry,
		})
	}

	for _, p := range posted {
		got := k.GetRawPrices(sdkctx, p.marketID)
		require.Len(t, got, 1, "market %s should see only its own posted price", p.marketID)
		require.Equal(t, p.marketID, got[0].MarketId)
		require.Equal(t, math.LegacyMustNewDecFromStr(p.price), got[0].Price)
	}

	require.Empty(t, k.GetRawPrices(sdkctx, "cn:eth:usd"), "a market with no posted price sees none")
}

// A market id that is a string prefix of another must not pick up the longer one's prices.  The "/"
// separator in PostedPriceKey is what guarantees this.
func TestGetRawPricesPrefixIsNotAmbiguous(t *testing.T) {
	k, ctx := keepertest.PricefeedKeeper(t)
	sdkctx := sdk.UnwrapSDKContext(ctx)

	oracle := sdk.AccAddress("oracle")
	expiry := sdkctx.BlockTime().Add(24 * time.Hour)

	k.SetPostedPrice(ctx, types.PostedPrice{
		MarketId:      "cn:qdn",
		OracleAddress: oracle,
		Price:         math.LegacyMustNewDecFromStr("1"),
		Expiry:        expiry,
	})
	k.SetPostedPrice(ctx, types.PostedPrice{
		MarketId:      "cn:qdn:php",
		OracleAddress: oracle,
		Price:         math.LegacyMustNewDecFromStr("2"),
		Expiry:        expiry,
	})

	short := k.GetRawPrices(sdkctx, "cn:qdn")
	require.Len(t, short, 1)
	require.Equal(t, math.LegacyMustNewDecFromStr("1"), short[0].Price)

	long := k.GetRawPrices(sdkctx, "cn:qdn:php")
	require.Len(t, long, 1)
	require.Equal(t, math.LegacyMustNewDecFromStr("2"), long[0].Price)
}
