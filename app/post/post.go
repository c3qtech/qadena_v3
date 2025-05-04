package post

import (
	errorsmod "cosmossdk.io/errors"

	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"

	qadenamodulekeeper "qadena/x/qadena/keeper"
)

// HandlerOptions are the options required for constructing a default SDK AnteHandler.
type HandlerOptions struct {
	QadenaKeeper *qadenamodulekeeper.Keeper
}

// NewAnteHandler returns an AnteHandler that checks and increments sequence
// numbers, checks signatures & account numbers, and deducts fees from the first
// signer.
func NewPostHandler(options HandlerOptions) (sdk.PostHandler, error) {
	if options.QadenaKeeper == nil {
		return nil, errorsmod.Wrap(sdkerrors.ErrLogic, "qadena keeper is required for qadena builder")
	}

	postDecorators := []sdk.PostDecorator{
		options.QadenaKeeper,
	}

	return sdk.ChainPostDecorators(postDecorators...), nil
}
