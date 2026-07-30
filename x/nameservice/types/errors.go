package types

// DONTCOVER

import (
	sdkerrors "cosmossdk.io/errors"
)

// x/nameservice module sentinel errors
var (
	ErrInvalidSigner = sdkerrors.Register(ModuleName, 1100, "expected gov account as only signer for proposal message")
	ErrSample        = sdkerrors.Register(ModuleName, 1101, "sample error")

	ErrNameBindingNotExists = sdkerrors.Register(ModuleName, 1102, "Name binding does not exist")
	ErrNameBindingNotOwner  = sdkerrors.Register(ModuleName, 1103, "Not the owner of this name binding")
)
