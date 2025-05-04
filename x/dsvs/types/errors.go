package types

// DONTCOVER

import (
	sdkerrors "cosmossdk.io/errors"
)

// x/dsvs module sentinel errors
var (
	ErrInvalidSigner               = sdkerrors.Register(ModuleName, 1100, "Expected gov account as only signer for proposal message")
	ErrDocumentExists              = sdkerrors.Register(ModuleName, 1101, "Document already exists")
	ErrHashExists                  = sdkerrors.Register(ModuleName, 1102, "Hash already exists")
	ErrDocumentNotFound            = sdkerrors.Register(ModuleName, 1103, "Document not found")
	ErrNotCurrentHash              = sdkerrors.Register(ModuleName, 1104, "Invalid not current hash")
	ErrInvalidDocument             = sdkerrors.Register(ModuleName, 1105, "Invalid document")
	ErrHashDuplicate               = sdkerrors.Register(ModuleName, 1106, "Hash duplicate")
	ErrInvalidVShare               = sdkerrors.Register(ModuleName, 1107, "Invalid VShare")
	ErrPubKIDNotExists             = sdkerrors.Register(ModuleName, 1108, "PubKID does not exist")
	ErrPubKNotExists               = sdkerrors.Register(ModuleName, 1109, "PubK does not exist")
	ErrServiceProviderUnauthorized = sdkerrors.Register(ModuleName, 1110, "Unauthorized service provider")
	ErrWalletNotFound              = sdkerrors.Register(ModuleName, 1111, "Wallet not found")
	ErrUnauthorized                = sdkerrors.Register(ModuleName, 1112, "Unauthorized")
	ErrDocumentFullySigned         = sdkerrors.Register(ModuleName, 1113, "Document fully signed")
)
