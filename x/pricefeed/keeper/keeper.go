package keeper

import (
	"fmt"

	"cosmossdk.io/store/prefix"
	storetypes "cosmossdk.io/store/types"
	"github.com/cosmos/cosmos-sdk/runtime"

	"cosmossdk.io/core/store"
	"cosmossdk.io/log"
	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"

	pricefeedtypes "qadena_v3/x/pricefeed/types"
	"sort"
	"time"

	"cosmossdk.io/math"
	errorsmod "github.com/pkg/errors" // Add this line to import the errorsmod package
)

type (
	Keeper struct {
		cdc          codec.BinaryCodec
		storeService store.KVStoreService
		logger       log.Logger

		// the address capable of executing a MsgUpdateParams message. Typically, this
		// should be the x/gov module account.
		authority string
	}
)

func NewKeeper(
	cdc codec.BinaryCodec,
	storeService store.KVStoreService,
	logger log.Logger,
	authority string,

) Keeper {
	if _, err := sdk.AccAddressFromBech32(authority); err != nil {
		panic(fmt.Sprintf("invalid authority address: %s", authority))
	}

	return Keeper{
		cdc:          cdc,
		storeService: storeService,
		authority:    authority,
		logger:       logger,
	}
}

// GetAuthority returns the module's authority.
func (k Keeper) GetAuthority() string {
	return k.authority
}

// Logger returns a module-specific logger.
func (k Keeper) Logger() log.Logger {
	return k.logger.With("module", fmt.Sprintf("x/%s", pricefeedtypes.ModuleName))
}

// GetMarkets returns the markets from params
func (k Keeper) GetMarkets(ctx sdk.Context) pricefeedtypes.Markets {
	return k.GetParams(ctx).Markets
}

// GetOracles returns the oracles in the pricefeed store
func (k Keeper) GetOracles(ctx sdk.Context, marketID string) ([]sdk.AccAddress, error) {
	for _, m := range k.GetMarkets(ctx) {
		if marketID == m.MarketId {
			return m.Oracles, nil
		}
	}
	return nil, errorsmod.Wrap(pricefeedtypes.ErrInvalidMarket, marketID)
}

// GetOracle returns the oracle from the store or an error if not found
func (k Keeper) GetOracle(ctx sdk.Context, marketID string, address sdk.AccAddress) (sdk.AccAddress, error) {
	oracles, err := k.GetOracles(ctx, marketID)
	if err != nil {
		// Error already wrapped
		return nil, err
	}
	for _, addr := range oracles {
		if addr.Equals(address) {
			return addr, nil
		}
	}
	return nil, errorsmod.Wrap(pricefeedtypes.ErrInvalidOracle, address.String())
}

// GetMarket returns the market if it is in the pricefeed system
func (k Keeper) GetMarket(ctx sdk.Context, marketID string) (pricefeedtypes.Market, bool) {
	markets := k.GetMarkets(ctx)

	for i := range markets {
		if markets[i].MarketId == marketID {
			return markets[i], true
		}
	}
	return pricefeedtypes.Market{}, false
}

// GetAuthorizedAddresses returns a list of addresses that have special authorization within this module, eg the oracles of all markets.
func (k Keeper) GetAuthorizedAddresses(ctx sdk.Context) []sdk.AccAddress {
	var oracles []sdk.AccAddress
	uniqueOracles := map[string]bool{}

	for _, m := range k.GetMarkets(ctx) {
		for _, o := range m.Oracles {
			// de-dup list of oracles
			if _, found := uniqueOracles[o.String()]; !found {
				oracles = append(oracles, o)
			}
			uniqueOracles[o.String()] = true
		}
	}
	return oracles
}

// SetPrice updates the posted price for a specific oracle
func (k Keeper) SetPrice(
	ctx sdk.Context,
	oracle sdk.AccAddress,
	marketID string,
	price math.LegacyDec,
	expiry time.Time,
) (pricefeedtypes.PostedPrice, error) {
	// If the expiry is less than or equal to the current blockheight, we consider the price valid
	if !expiry.After(ctx.BlockTime()) {
		return pricefeedtypes.PostedPrice{}, pricefeedtypes.ErrExpired
	}

	newRawPrice := pricefeedtypes.PostedPrice{marketID, oracle, price, expiry}

	// Emit an event containing the oracle's new price
	ctx.EventManager().EmitEvent(
		sdk.NewEvent(
			pricefeedtypes.EventTypeOracleUpdatedPrice,
			sdk.NewAttribute(pricefeedtypes.AttributeMarketID, marketID),
			sdk.NewAttribute(pricefeedtypes.AttributeOracle, oracle.String()),
			sdk.NewAttribute(pricefeedtypes.AttributeMarketPrice, price.String()),
			sdk.NewAttribute(pricefeedtypes.AttributeExpiry, expiry.UTC().String()),
		),
	)

	k.SetPostedPrice(ctx, newRawPrice)

	// Sets the raw price for a single oracle instead of an array of all oracle's raw prices
	return newRawPrice, nil
}

// SetCurrentPrices updates the price of an asset to the median of all valid oracle inputs
func (k Keeper) SetCurrentPrices(ctx sdk.Context, marketID string) error {
	_, ok := k.GetMarket(ctx, marketID)
	if !ok {
		return errorsmod.Wrap(pricefeedtypes.ErrInvalidMarket, marketID)
	}
	// store current price
	validPrevPrice := true
	prevPrice, err := k.GetCurrentPrice(ctx, marketID)
	if err != nil {
		validPrevPrice = false
	}

	prices := k.GetRawPrices(ctx, marketID)

	var notExpiredPrices []pricefeedtypes.CurrentPrice
	// filter out expired prices
	for _, v := range prices {
		if v.Expiry.After(ctx.BlockTime()) {
			notExpiredPrices = append(notExpiredPrices, pricefeedtypes.CurrentPrice{v.MarketId, v.Price})
		}
	}

	if len(notExpiredPrices) == 0 {
		// NOTE: The current price stored will continue storing the most recent (expired)
		// price if this is not set.
		// This zero's out the current price stored value for that market and ensures
		// that CDP methods that GetCurrentPrice will return error.
		k.setCurrentPrice(ctx, marketID, pricefeedtypes.CurrentPrice{})
		return pricefeedtypes.ErrNoValidPrice
	}

	medianPrice := k.CalculateMedianPrice(notExpiredPrices)

	// check case that market price was not set in genesis
	if validPrevPrice && !medianPrice.Equal(prevPrice.Price) {
		// only emit event if price has changed
		ctx.EventManager().EmitEvent(
			sdk.NewEvent(
				pricefeedtypes.EventTypeMarketPriceUpdated,
				sdk.NewAttribute(pricefeedtypes.AttributeMarketID, marketID),
				sdk.NewAttribute(pricefeedtypes.AttributeMarketPrice, medianPrice.String()),
			),
		)
	}

	currentPrice := pricefeedtypes.CurrentPrice{marketID, medianPrice}
	k.setCurrentPrice(ctx, marketID, currentPrice)

	return nil
}

// SetCurrentPricesForAllMarkets updates the price of an asset to the median of all valid oracle inputs
func (k Keeper) SetCurrentPricesForAllMarkets(ctx sdk.Context) {
	orderedMarkets := []string{}
	marketPricesByID := make(map[string]pricefeedtypes.CurrentPrices)

	for _, market := range k.GetMarkets(ctx) {
		if market.Active {
			orderedMarkets = append(orderedMarkets, market.MarketId)
			marketPricesByID[market.MarketId] = pricefeedtypes.CurrentPrices{}
		}
	}

	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, pricefeedtypes.KeyPrefix(pricefeedtypes.PostedPriceKeyPrefix))
	iterator := storetypes.KVStorePrefixIterator(store, []byte{})

	for ; iterator.Valid(); iterator.Next() {
		var postedPrice pricefeedtypes.PostedPrice
		k.cdc.MustUnmarshal(iterator.Value(), &postedPrice)

		prices, found := marketPricesByID[postedPrice.MarketId]
		if !found {
			continue
		}

		// filter out expired prices
		if postedPrice.Expiry.After(ctx.BlockTime()) {
			marketPricesByID[postedPrice.MarketId] = append(prices, pricefeedtypes.CurrentPrice{postedPrice.MarketId, postedPrice.Price})
		}
	}
	iterator.Close()

	for _, marketID := range orderedMarkets {
		// store current price
		validPrevPrice := true
		prevPrice, err := k.GetCurrentPrice(ctx, marketID)
		if err != nil {
			validPrevPrice = false
		}

		notExpiredPrices, _ := marketPricesByID[marketID]

		if len(notExpiredPrices) == 0 {
			// NOTE: The current price stored will continue storing the most recent (expired)
			// price if this is not set.
			// This zero's out the current price stored value for that market and ensures
			// that CDP methods that GetCurrentPrice will return error.
			k.setCurrentPrice(ctx, marketID, pricefeedtypes.CurrentPrice{})
			continue
		}

		medianPrice := k.CalculateMedianPrice(notExpiredPrices)

		// check case that market price was not set in genesis
		//if validPrevPrice && !medianPrice.Equal(prevPrice.Price) {
		if validPrevPrice && !medianPrice.Equal(prevPrice.Price) {
			// only emit event if price has changed
			ctx.EventManager().EmitEvent(
				sdk.NewEvent(
					pricefeedtypes.EventTypeMarketPriceUpdated,
					sdk.NewAttribute(pricefeedtypes.AttributeMarketID, marketID),
					sdk.NewAttribute(pricefeedtypes.AttributeMarketPrice, medianPrice.String()),
				),
			)
		}

		currentPrice := pricefeedtypes.CurrentPrice{marketID, medianPrice}
		k.setCurrentPrice(ctx, marketID, currentPrice)
	}
}

func (k Keeper) setCurrentPrice(ctx sdk.Context, marketID string, currentPrice pricefeedtypes.CurrentPrice) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, pricefeedtypes.KeyPrefix(pricefeedtypes.CurrentPriceKeyPrefix))

	store.Set(pricefeedtypes.CurrentPriceKey(marketID), k.cdc.MustMarshal(&currentPrice))
}

// CalculateMedianPrice calculates the median prices for the input prices.
func (k Keeper) CalculateMedianPrice(prices []pricefeedtypes.CurrentPrice) math.LegacyDec {
	l := len(prices)

	if l == 1 {
		// Return immediately if there's only one price
		return prices[0].Price
	}
	// sort the prices
	sort.Slice(prices, func(i, j int) bool {
		return prices[i].Price.LT(prices[j].Price)
	})
	// for even numbers of prices, the median is calculated as the mean of the two middle prices
	if l%2 == 0 {
		median := k.calculateMeanPrice(prices[l/2-1], prices[l/2])
		return median
	}
	// for odd numbers of prices, return the middle element
	return prices[l/2].Price
}

func (k Keeper) calculateMeanPrice(priceA, priceB pricefeedtypes.CurrentPrice) math.LegacyDec {
	sum := priceA.Price.Add(priceB.Price)
	mean := sum.Quo(math.LegacyNewDec(2))
	return mean
}

// GetCurrentPrice fetches the current median price of all oracles for a specific market
func (k Keeper) GetCurrentPrice(ctx sdk.Context, marketID string) (pricefeedtypes.CurrentPrice, error) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, pricefeedtypes.KeyPrefix(pricefeedtypes.CurrentPriceKeyPrefix))

	bz := store.Get(pricefeedtypes.CurrentPriceKey(marketID))

	if bz == nil {
		return pricefeedtypes.CurrentPrice{}, pricefeedtypes.ErrNoValidPrice
	}
	var price pricefeedtypes.CurrentPrice
	err := k.cdc.Unmarshal(bz, &price)
	if err != nil {
		return pricefeedtypes.CurrentPrice{}, err
	}
	if price.Price.Equal(math.LegacyZeroDec()) {
		return pricefeedtypes.CurrentPrice{}, pricefeedtypes.ErrNoValidPrice
	}
	return price, nil
}

// IterateCurrentPrices iterates over all current price objects in the store and performs a callback function
func (k Keeper) IterateCurrentPrices(ctx sdk.Context, cb func(cp pricefeedtypes.CurrentPrice) (stop bool)) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, pricefeedtypes.KeyPrefix(pricefeedtypes.CurrentPriceKeyPrefix))
	iterator := storetypes.KVStorePrefixIterator(store, []byte{})
	defer iterator.Close()
	for ; iterator.Valid(); iterator.Next() {
		var cp pricefeedtypes.CurrentPrice
		k.cdc.MustUnmarshal(iterator.Value(), &cp)
		if cb(cp) {
			break
		}
	}
}

// GetCurrentPrices returns all current price objects from the store
func (k Keeper) GetCurrentPrices(ctx sdk.Context) pricefeedtypes.CurrentPrices {
	var cps pricefeedtypes.CurrentPrices
	k.IterateCurrentPrices(ctx, func(cp pricefeedtypes.CurrentPrice) (stop bool) {
		cps = append(cps, cp)
		return false
	})
	return cps
}

// GetRawPrices fetches the set of all prices posted by oracles for an asset
func (k Keeper) GetRawPrices(ctx sdk.Context, marketId string) pricefeedtypes.PostedPrices {
	var pps pricefeedtypes.PostedPrices
	k.IterateRawPricesByMarket(ctx, marketId, func(pp pricefeedtypes.PostedPrice) (stop bool) {
		pps = append(pps, pp)
		return false
	})
	return pps
}

// IterateRawPrices iterates over all raw prices in the store and performs a callback function
func (k Keeper) IterateRawPricesByMarket(ctx sdk.Context, marketId string, cb func(record pricefeedtypes.PostedPrice) (stop bool)) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, pricefeedtypes.KeyPrefix(pricefeedtypes.PostedPriceKeyPrefix))
	iterator := storetypes.KVStorePrefixIterator(store, []byte{})
	defer iterator.Close()
	for ; iterator.Valid(); iterator.Next() {
		var record pricefeedtypes.PostedPrice
		k.cdc.MustUnmarshal(iterator.Value(), &record)
		if cb(record) {
			break
		}
	}
}
