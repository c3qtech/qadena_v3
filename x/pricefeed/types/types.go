package types

// PostedPrices is a slice of PostedPrice
type PostedPrices []PostedPrice
type Markets []Market
type CurrentPrices []CurrentPrice

// Pricefeed module event types
const (
	EventTypeMarketPriceUpdated = "market_price_updated"
	EventTypeOracleUpdatedPrice = "oracle_updated_price"
	EventTypeNoValidPrices      = "no_valid_prices"

	AttributeValueCategory = ModuleName
	AttributeMarketID      = "market_id"
	AttributeMarketPrice   = "market_price"
	AttributeOracle        = "oracle"
	AttributeExpiry        = "expiry"
)
