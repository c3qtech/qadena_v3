package keeper_test

import (
	"errors"
	"testing"

	cosmosmath "cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"

	keepertest "github.com/c3qtech/qadena_v3/testutil/keeper"
	pricefeedtypes "github.com/c3qtech/qadena_v3/x/pricefeed/types"
	"github.com/c3qtech/qadena_v3/x/qadena/keeper"
	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

// stubPricefeed implements types.PricefeedKeeper so the conversion can be driven into each of its
// branches without standing up a chain.
type stubPricefeed struct {
	price cosmosmath.LegacyDec
	err   error
}

func (s stubPricefeed) GetCurrentPrice(_ sdk.Context, marketID string) (pricefeedtypes.CurrentPrice, error) {
	if s.err != nil {
		return pricefeedtypes.CurrentPrice{}, s.err
	}
	return pricefeedtypes.CurrentPrice{MarketId: marketID, Price: s.price}, nil
}

func keeperWithPrice(t testing.TB, pf types.PricefeedKeeper) (keeper.Keeper, sdk.Context) {
	return keepertest.QadenaKeeperWithPricefeed(t, pf)
}

// A fiat fee with no price behind it must be REFUSED, not converted at a zero rate.
//
// This is the regression: the old code substituted a zero base price on error and then evaluated
// feeAmount.Quo(basePrice).  LegacyDec.Quo panics on a zero divisor, so create-credential,
// create-bulk-credentials and update-credential would panic rather than return.  The assertion that
// matters here is as much "does not panic" as "returns the right error".
func TestConvertFeeToQadenaFailsClosedWhenPriceMissing(t *testing.T) {
	k, ctx := keeperWithPrice(t, stubPricefeed{err: pricefeedtypes.ErrNoValidPrice})

	fee, err := sdk.ParseDecCoin("30php")
	require.NoError(t, err)

	require.NotPanics(t, func() {
		_, err = k.ConvertFeeToQadena(ctx, fee)
	}, "a missing price must not panic; the zero-rate fallback used to divide by zero")

	require.Error(t, err)
	require.True(t, errors.Is(err, types.ErrNoPriceForDenom),
		"expected ErrNoPriceForDenom, got %v", err)
}

// A price that exists but is zero is treated exactly like a missing one.  GetCurrentPrice is
// supposed to filter these, but the conversion must not depend on that -- a zero reaching the
// division is precisely the case being defended against.
func TestConvertFeeToQadenaFailsClosedWhenPriceZero(t *testing.T) {
	k, ctx := keeperWithPrice(t, stubPricefeed{price: cosmosmath.LegacyZeroDec()})

	fee, err := sdk.ParseDecCoin("30php")
	require.NoError(t, err)

	require.NotPanics(t, func() {
		_, err = k.ConvertFeeToQadena(ctx, fee)
	}, "a zero price must not reach the division")

	require.Error(t, err)
	require.True(t, errors.Is(err, types.ErrNoPriceForDenom),
		"expected ErrNoPriceForDenom, got %v", err)
}

// A negative price is nonsense but must fail the same way rather than producing a negative fee.
func TestConvertFeeToQadenaFailsClosedWhenPriceNegative(t *testing.T) {
	k, ctx := keeperWithPrice(t, stubPricefeed{price: cosmosmath.LegacyNewDec(-1)})

	fee, err := sdk.ParseDecCoin("30php")
	require.NoError(t, err)

	_, err = k.ConvertFeeToQadena(ctx, fee)
	require.Error(t, err)
	require.True(t, errors.Is(err, types.ErrNoPriceForDenom),
		"expected ErrNoPriceForDenom, got %v", err)
}

// The happy path still converts, and converts correctly: 30php at 0.613610 qdn/php is 48.89 qdn.
// Without this, "fails closed" could be satisfied by a function that always fails.
func TestConvertFeeToQadenaConvertsAtTheQuotedRate(t *testing.T) {
	rate := cosmosmath.LegacyMustNewDecFromStr("0.613610")
	k, ctx := keeperWithPrice(t, stubPricefeed{price: rate})

	fee, err := sdk.ParseDecCoin("30php")
	require.NoError(t, err)

	got, err := k.ConvertFeeToQadena(ctx, fee)
	require.NoError(t, err)
	require.Equal(t, types.QadenaTokenDenom, got.Denom)

	want := cosmosmath.LegacyMustNewDecFromStr("30").Quo(rate)
	require.True(t, got.Amount.Equal(want),
		"converted to %s, expected %s", got.Amount, want)
}

// A fee already in the chain's own denom needs no price at all -- it must not consult the pricefeed,
// so an outage cannot block operations that were never going to convert.
func TestConvertFeeToQadenaSkipsPricefeedForNativeDenom(t *testing.T) {
	// a stub that fails every lookup: reaching it at all is the failure
	k, ctx := keeperWithPrice(t, stubPricefeed{err: errors.New("pricefeed must not be consulted")})

	for _, denom := range []string{types.QadenaTokenDenom, types.AQadenaTokenDenom} {
		fee, err := sdk.ParseDecCoin("30" + denom)
		require.NoError(t, err)

		got, err := k.ConvertFeeToQadena(ctx, fee)
		require.NoError(t, err, "a %s fee must not need a price", denom)
		require.Equal(t, fee, got, "a %s fee must pass through unchanged", denom)
	}
}
