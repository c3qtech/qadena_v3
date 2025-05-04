package types

// DONTCOVER

import (
	sdkerrors "cosmossdk.io/errors"
)

// x/pricefeed module sentinel errors
var (
	ErrInvalidSigner = sdkerrors.Register(ModuleName, 1100, "expected gov account as only signer for proposal message")

	// ErrEmptyInput error for empty input
	ErrEmptyInput = sdkerrors.Register(ModuleName, 1101, "input must not be empty")
	// ErrExpired error for posted price messages with expired price
	ErrExpired = sdkerrors.Register(ModuleName, 1102, "price is expired")
	// ErrNoValidPrice error for posted price messages with expired price
	ErrNoValidPrice = sdkerrors.Register(ModuleName, 1103, "all input prices are expired")
	// ErrInvalidMarket error for posted price messages for invalid markets
	ErrInvalidMarket = sdkerrors.Register(ModuleName, 1104, "market does not exist")
	// ErrInvalidOracle error for posted price messages for invalid oracles
	ErrInvalidOracle = sdkerrors.Register(ModuleName, 1106, "oracle does not exist or not authorized")
	// ErrAssetNotFound error for not found asset
	ErrAssetNotFound = sdkerrors.Register(ModuleName, 1107, "asset not found")
)
