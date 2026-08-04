package types

import (
	"context"

	pricefeedtypes "github.com/c3qtech/qadena_v3/x/pricefeed/types"

	sdk "github.com/cosmos/cosmos-sdk/types"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
)

// AccountKeeper defines the expected interface for the Account module.
type AccountKeeper interface {
	GetAccount(context.Context, sdk.AccAddress) sdk.AccountI // only used for simulation
	// Methods imported from account should be defined here

	GetModuleAddress(moduleName string) sdk.AccAddress
}

// BankKeeper defines the expected interface for the Bank module.
type BankKeeper interface {
	SpendableCoins(context.Context, sdk.AccAddress) sdk.Coins
	// Methods imported from bank should be defined here

	GetDenomMetaData(ctx context.Context, denom string) (banktypes.Metadata, bool)

	GetBalance(ctx context.Context, addr sdk.AccAddress, denom string) sdk.Coin
	LockedCoins(ctx context.Context, addr sdk.AccAddress) sdk.Coins

	SendCoinsFromModuleToAccount(ctx context.Context, senderModule string, recipientAddr sdk.AccAddress, amt sdk.Coins) error
	SendCoinsFromAccountToModule(ctx context.Context, senderAddr sdk.AccAddress, recipientModule string, amt sdk.Coins) error
}

type PricefeedKeeper interface {
	GetCurrentPrice(ctx sdk.Context, marketID string) (pricefeedtypes.CurrentPrice, error)
}

// ContractInfoSource answers the one question the scanned-contract whitelist needs about wasm state:
// is this address a contract, and what code is it running right now.
//
// Narrowed to that on purpose.  The alternative is importing wasmd's keeper into x/qadena, which
// drags the whole wasm dependency into a module that otherwise knows nothing about it, and creates a
// build cycle with app wiring.  app/ supplies the implementation because that is where wasmd already
// lives.
type ContractInfoSource interface {
	// ContractCodeID returns the live code ID for a wasm contract.  isContract is false for anything
	// that is not one -- a plain account, a module account, an EVM account.
	ContractCodeID(ctx sdk.Context, addr sdk.AccAddress) (codeID uint64, isContract bool)
}

// ContractInfoHolder carries a ContractInfoSource that is set AFTER the qadena keeper is built.
//
// The keeper is constructed by depinject well before wasmd's keeper exists, and Keeper is copied by
// value into the msg server and the module -- so a plain field set later would be written on one
// copy and read on another.  Holding a pointer means every copy shares the same slot, which is the
// same reason cachedCreator and cachedGasPriceInAQDN are pointers.
type ContractInfoHolder struct {
	Source ContractInfoSource
}

// ParamSubspace defines the expected Subspace interface for parameters.
type ParamSubspace interface {
	Get(context.Context, []byte, interface{})
	Set(context.Context, []byte, interface{})
}
