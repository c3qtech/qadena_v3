package ante

import (
	"strings"

	errorsmod "cosmossdk.io/errors"
	storetypes "cosmossdk.io/store/types"
	txsigning "cosmossdk.io/x/tx/signing"

	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	"github.com/cosmos/cosmos-sdk/x/auth/types"

	qadenamodulekeeper "github.com/c3qtech/qadena_v3/x/qadena/keeper"

	authante "github.com/cosmos/cosmos-sdk/x/auth/ante"

	corestoretypes "cosmossdk.io/core/store"
	wasmkeeper "github.com/CosmWasm/wasmd/x/wasm/keeper"
	wasmTypes "github.com/CosmWasm/wasmd/x/wasm/types"
)

// aminoCodecPanicMarker identifies the one panic sigVerifyNoPanic is allowed to absorb.
// It is the message legacytx.StdSignBytes panics with when RegressionTestingAminoCodec
// is nil (vendor/github.com/cosmos/cosmos-sdk/x/auth/migrations/legacytx/stdsign.go).
const aminoCodecPanicMarker = "RegressionTestingAminoCodec"

// sigVerifyNoPanic turns the vendored amino panic into an ordinary signature error.
//
// cosmos/evm's PubKey.VerifySignature falls through to EIP-712 verification on ANY
// plain-ECDSA failure, and that path reaches legacytx.StdSignBytes, which panics
// because RegressionTestingAminoCodec is never assigned.  So an ordinary bad
// signature -- a chain-id mismatch, say -- surfaces at the broadcaster as a recovered
// panic with a goroutine dump instead of the failure it actually is.
//
// Assigning that codec would also stop the panic, but it would switch ON a
// verification path that is dead today, and qadena's Msg types are not registered as
// amino concrete types, so their sign bytes carry no type discriminator -- a signature
// would bind field values but not the message type.  Recovering here keeps that path
// dead and still reports the real cause.
//
// Only the amino panic is absorbed; anything else is re-panicked untouched, notably
// storetypes.ErrorOutOfGas, which baseapp must handle itself.
type sigVerifyNoPanic struct {
	inner sdk.AnteDecorator
}

func (d sigVerifyNoPanic) AnteHandle(ctx sdk.Context, tx sdk.Tx, simulate bool, next sdk.AnteHandler) (newCtx sdk.Context, err error) {
	defer func() {
		r := recover()
		if r == nil {
			return
		}

		e, ok := r.(error)
		if !ok || !strings.Contains(e.Error(), aminoCodecPanicMarker) {
			panic(r)
		}

		newCtx = ctx
		err = errorsmod.Wrap(sdkerrors.ErrUnauthorized, "signature verification failed")
	}()

	return d.inner.AnteHandle(ctx, tx, simulate, next)
}

// HandlerOptions are the options required for constructing a default SDK AnteHandler.
type HandlerOptions struct {
	AccountKeeper          authante.AccountKeeper
	BankKeeper             types.BankKeeper
	ExtensionOptionChecker authante.ExtensionOptionChecker
	FeegrantKeeper         authante.FeegrantKeeper
	SignModeHandler        *txsigning.HandlerMap
	SigGasConsumer         func(meter storetypes.GasMeter, sig signing.SignatureV2, params types.Params) error
	TxFeeChecker           authante.TxFeeChecker
	QadenaKeeper           *qadenamodulekeeper.Keeper
	NodeConfig             *wasmTypes.NodeConfig
	TXCounterStoreService  corestoretypes.KVStoreService
	WasmKeeper             *wasmkeeper.Keeper
	SigVerifyOptions       []authante.SigVerificationDecoratorOption
}

// NewAnteHandler returns an AnteHandler that checks and increments sequence
// numbers, checks signatures & account numbers, and deducts fees from the first
// signer.
func NewAnteHandler(options HandlerOptions) (sdk.AnteHandler, error) {
	if options.QadenaKeeper == nil {
		return nil, errorsmod.Wrap(sdkerrors.ErrLogic, "qadena keeper is required for ante builder")
	}

	if options.AccountKeeper == nil {
		return nil, errorsmod.Wrap(sdkerrors.ErrLogic, "account keeper is required for ante builder")
	}

	if options.BankKeeper == nil {
		return nil, errorsmod.Wrap(sdkerrors.ErrLogic, "bank keeper is required for ante builder")
	}

	if options.SignModeHandler == nil {
		return nil, errorsmod.Wrap(sdkerrors.ErrLogic, "sign mode handler is required for ante builder")
	}

	if options.NodeConfig == nil {
		return nil, errorsmod.Wrap(sdkerrors.ErrLogic, "wasm config is required for ante builder")
	}
	if options.TXCounterStoreService == nil {
		return nil, errorsmod.Wrap(sdkerrors.ErrLogic, "wasm store service is required for ante builder")
	}

	anteDecorators := []sdk.AnteDecorator{
		authante.NewSetUpContextDecorator(),                                              // outermost AnteDecorator. SetUpContext must be called first
		wasmkeeper.NewLimitSimulationGasDecorator(options.NodeConfig.SimulationGasLimit), // after setup context to enforce limits early
		wasmkeeper.NewCountTXDecorator(options.TXCounterStoreService),
		wasmkeeper.NewGasRegisterDecorator(options.WasmKeeper.GetGasRegister()),
		wasmkeeper.NewTxContractsDecorator(),
		options.QadenaKeeper,
		authante.NewExtensionOptionsDecorator(options.ExtensionOptionChecker),
		authante.NewValidateBasicDecorator(),
		authante.NewTxTimeoutHeightDecorator(),
		authante.NewValidateMemoDecorator(options.AccountKeeper),
		authante.NewConsumeGasForTxSizeDecorator(options.AccountKeeper),
		authante.NewDeductFeeDecorator(options.AccountKeeper, options.BankKeeper, options.FeegrantKeeper, options.TxFeeChecker),
		authante.NewSetPubKeyDecorator(options.AccountKeeper), // SetPubKeyDecorator must be called before all signature verification decorators
		authante.NewValidateSigCountDecorator(options.AccountKeeper),
		authante.NewSigGasConsumeDecorator(options.AccountKeeper, options.SigGasConsumer),
		sigVerifyNoPanic{authante.NewSigVerificationDecorator(options.AccountKeeper, options.SignModeHandler, options.SigVerifyOptions...)},
		authante.NewIncrementSequenceDecorator(options.AccountKeeper),
	}

	return sdk.ChainAnteDecorators(anteDecorators...), nil
}
