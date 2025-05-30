package types

import (
	"context"

	qadenatypes "github.com/c3qtech/qadena_v3/x/qadena/types"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

type QadenaKeeper interface {
	// TODO Add methods imported from qadena should be defined here
	// RAV REMOVE THIS
	DUMMY_KEEPER_METHOD_NAMESERVICE()

	ValidateCredential(ctx sdk.Context, msg *qadenatypes.MsgBindCredential) (bool, error)
}

// AccountKeeper defines the expected interface for the Account module.
type AccountKeeper interface {
	GetAccount(context.Context, sdk.AccAddress) sdk.AccountI // only used for simulation
	// Methods imported from account should be defined here
}

// BankKeeper defines the expected interface for the Bank module.
type BankKeeper interface {
	SpendableCoins(context.Context, sdk.AccAddress) sdk.Coins
	// Methods imported from bank should be defined here
}

// ParamSubspace defines the expected Subspace interface for parameters.
type ParamSubspace interface {
	Get(context.Context, []byte, interface{})
	Set(context.Context, []byte, interface{})
}
