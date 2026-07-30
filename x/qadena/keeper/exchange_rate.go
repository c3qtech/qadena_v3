package keeper

import (
	errorsmod "cosmossdk.io/errors"
	cosmosmath "cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"
	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

// ExchangeRateToQadena returns the pricefeed rate for converting an amount denominated in `denom`
// into QadenaTokenDenom, and FAILS CLOSED when no usable rate exists.
//
// This replaces a fallback that every caller used to repeat inline:
//
//	cp, err := k.pricefeedKeeper.GetCurrentPrice(ctx, marketID)
//	if err != nil {
//	    basePrice = zero          // <-- the problem
//	} else {
//	    basePrice = cp.Price
//	}
//
// Substituting zero was wrong in two different ways, and the second is worse than the first:
//
//  1. Fee conversion then evaluated `feeAmount.Quo(basePrice)`.  LegacyDec.Quo panics on a zero
//     divisor, so create-credential, create-bulk-credentials and update-credential would panic --
//     recovered by baseapp, but surfacing as an opaque failure that consumed the whole gas limit.
//
//  2. EnclaveClientScanTransaction passes the rate to the enclave, which computes
//     usdCoinAmount = amount * rate.  A zero rate makes EVERY transfer evaluate as 0 USD, so the
//     suspicious-transaction threshold silently never fires.  That is an AML control failing OPEN
//     during a pricefeed outage, with nothing to indicate it happened.
//
// Failing closed is the right posture for both.  A missing price is a temporary, self-correcting
// condition -- an oracle stopped posting, or a seeded price expired -- and refusing the operation
// until it is fixed is far preferable to charging a fee nobody can compute or waving through
// transfers that were never scanned.
//
// A price of zero is treated the same as a missing one.  GetCurrentPrice already returns
// ErrNoValidPrice for a zero current price, but callers should not depend on that: a nil or
// non-positive Dec reaching the arithmetic below is exactly the case being defended against.
func (k Keeper) ExchangeRateToQadena(ctx sdk.Context, denom string) (cosmosmath.LegacyDec, error) {
	// "cn" for crypto markets, "fn" for fiat-to-fiat -- conversions into the chain's own token are
	// always the crypto side
	marketID := "cn:" + types.QadenaTokenDenom + ":" + denom

	cp, err := k.pricefeedKeeper.GetCurrentPrice(ctx, marketID)
	if err != nil {
		c.ContextError(ctx, "no pricefeed price for "+marketID+": "+err.Error())
		return cosmosmath.LegacyDec{}, errorsmod.Wrapf(types.ErrNoPriceForDenom,
			"market %s: %s", marketID, err.Error())
	}

	if cp.Price.IsNil() || !cp.Price.IsPositive() {
		c.ContextError(ctx, "non-positive pricefeed price for "+marketID)
		return cosmosmath.LegacyDec{}, errorsmod.Wrapf(types.ErrNoPriceForDenom,
			"market %s reported a non-positive price", marketID)
	}

	c.ContextDebug(ctx, "exchange rate "+types.QadenaTokenDenom+" to "+denom+" = "+cp.Price.String())
	return cp.Price, nil
}

// ConvertFeeToQadena converts a fee that may be denominated in fiat into QadenaTokenDenom.
//
// A fee already denominated in the chain's own token is returned unchanged, so callers do not have
// to special-case it.  Anything else requires a pricefeed rate and fails closed without one.
func (k Keeper) ConvertFeeToQadena(ctx sdk.Context, fee sdk.DecCoin) (sdk.DecCoin, error) {
	if fee.Denom == types.AQadenaTokenDenom || fee.Denom == types.QadenaTokenDenom {
		return fee, nil
	}

	rate, err := k.ExchangeRateToQadena(ctx, fee.Denom)
	if err != nil {
		return sdk.DecCoin{}, err
	}

	// rate is positive, checked above, so this cannot divide by zero
	converted, err := sdk.ParseDecCoin(fee.Amount.Quo(rate).String() + types.QadenaTokenDenom)
	if err != nil {
		c.ContextError(ctx, "error parsing converted fee coin "+err.Error())
		return sdk.DecCoin{}, err
	}

	c.ContextDebug(ctx, "fee "+fee.String()+" converted to "+converted.String())
	return converted, nil
}
