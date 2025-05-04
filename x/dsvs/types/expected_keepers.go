package types

import (
	"context"

	qadenatypes "github.com/c3qtech/qadena_v3/x/qadena/types"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

type QadenaKeeper interface {
	// TODO Add methods imported from qadena should be defined here
	DUMMY_KEEPER_METHOD_DSVS()
	EnclaveValidateAuthorizedSignatory(ctx sdk.Context, creator string, signatory *qadenatypes.VShareSignatory, currentSignatory []*qadenatypes.VShareSignatory) (bool, error)
	EnclaveValidateAuthorizedSigner(ctx sdk.Context, creator string, signer *qadenatypes.VShareSignatory, requiredSignatories []*qadenatypes.VShareSignatory, completedSignatories []*qadenatypes.VShareSignatory) (bool, error)
	GetIntervalPublicKeyID(ctx context.Context, nodeID string, nodeType string) (qadenatypes.IntervalPublicKeyID, bool)
	GetIntervalPublicKeyIDByPubKID(ctx context.Context, pubKID string) (qadenatypes.IntervalPublicKeyID, bool)
	GetPioneerJar(ctx context.Context, pioneerID string) (qadenatypes.PioneerJar, bool)
	GetPublicKey(ctx context.Context, pubKID string, pubKType string) (qadenatypes.PublicKey, bool)
	GetWallet(ctx context.Context, walletID string) (val qadenatypes.Wallet, found bool)
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
