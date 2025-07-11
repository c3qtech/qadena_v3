package types

// DONTCOVER

import (
	sdkerrors "cosmossdk.io/errors"
)

// x/qadena module sentinel errors
var (
	ErrInvalidSigner = sdkerrors.Register(ModuleName, 1100, "expected gov account as only signer for proposal message")

	ErrPublicKeyAlreadyExists        = sdkerrors.Register(ModuleName, 1102, "Public key already exists")
	ErrInvalidCreator                = sdkerrors.Register(ModuleName, 1103, "Creator address is invalid")
	ErrInvalidPubKType               = sdkerrors.Register(ModuleName, 1104, "Invalid PubK type")
	ErrInvalidIntervalPubKIdNodeType = sdkerrors.Register(ModuleName, 1105, "Invalid Interval PubK Id Node type")
	ErrPioneerNotExists              = sdkerrors.Register(ModuleName, 1106, "Pioneer does not exist")
	ErrPubKIDNotExists               = sdkerrors.Register(ModuleName, 1107, "PubKID does not exist")
	ErrInvalidDstEWalletID           = sdkerrors.Register(ModuleName, 1108, "Invalid destination EWalletID")
	ErrGenericTreasury               = sdkerrors.Register(ModuleName, 1109, "Treasury generic error")
	ErrGenericEncryption             = sdkerrors.Register(ModuleName, 1110, "Encryption generic error")
	ErrGenericPedersen               = sdkerrors.Register(ModuleName, 1111, "Pedersen generic error")

	ErrWalletNotExists = sdkerrors.Register(ModuleName, 1112, "Wallet does not exist")

	ErrInvalidWallet = sdkerrors.Register(ModuleName, 1113, "Invalid Wallet")

	ErrWalletExists        = sdkerrors.Register(ModuleName, 1114, "Wallet already exists")
	ErrCredentialExists    = sdkerrors.Register(ModuleName, 1115, "Credential already exists")
	ErrInvalidCredential   = sdkerrors.Register(ModuleName, 1116, "Invalid Credential")
	ErrCredentialClaimed   = sdkerrors.Register(ModuleName, 1117, "Credential already claimed")
	ErrCredentialNotExists = sdkerrors.Register(ModuleName, 1118, "Credential does not exist")
	ErrGenericTransaction  = sdkerrors.Register(ModuleName, 1119, "Invalid transaction")

	ErrKeyNotFound = sdkerrors.Register(ModuleName, 1120, "Key not found")

	ErrInvalidEnclave = sdkerrors.Register(ModuleName, 1121, "Invalid enclave")

	ErrRemoteReportNotVerified = sdkerrors.Register(ModuleName, 1122, "Cannot validate remote report")

	ErrMismatchCredential = sdkerrors.Register(ModuleName, 1123, "Mismatch credential")

	ErrGenericEnclave = sdkerrors.Register(ModuleName, 1124, "Generic enclave error")

	ErrGenericScan = sdkerrors.Register(ModuleName, 1125, "Generic scan error")

	ErrInvalidTransfer = sdkerrors.Register(ModuleName, 1126, "Invalid transfer")

	ErrInvalidRecoverKey = sdkerrors.Register(ModuleName, 1127, "Invalid recover key")

	ErrInvalidSignRecoverKey = sdkerrors.Register(ModuleName, 1128, "Invalid sign recover key")

	ErrInvalidQueryGetRecoverKey = sdkerrors.Register(ModuleName, 1129, "Invalid get recover key")

	ErrInvalidQueryRecoverKeyShare = sdkerrors.Register(ModuleName, 1130, "Invalid query recover key share")

	ErrRangeProofValidation = sdkerrors.Register(ModuleName, 1131, "Committed value out of range")

	ErrVShareCreation = sdkerrors.Register(ModuleName, 1132, "Error while making bind")

	ErrVShareVerification = sdkerrors.Register(ModuleName, 1133, "Error verifying vshare")

	ErrInvalidEKYCAppWalletID = sdkerrors.Register(ModuleName, 1134, "Invalid EKYCAppWalletID")

	ErrInvalidEKYCProviderWalletID = sdkerrors.Register(ModuleName, 1135, "Invalid EKYCProviderWalletID")

	ErrInvalidOperation = sdkerrors.Register(ModuleName, 1136, "Invalid operation")

	ErrUnauthorizedSigner = sdkerrors.Register(ModuleName, 1137, "Unauthorized signer")

	ErrAlreadySigned = sdkerrors.Register(ModuleName, 1138, "Already signed")

	ErrPubKExists = sdkerrors.Register(ModuleName, 1139, "PubK already exists")

	ErrServiceProviderUnauthorized = sdkerrors.Register(ModuleName, 1140, "Unauthorized service provider")

	ErrUnauthorized = sdkerrors.Register(ModuleName, 1141, "Unauthorized")

	ErrInvalidVShare = sdkerrors.Register(ModuleName, 1142, "Invalid VShare")

	ErrServiceProviderAlreadyExists = sdkerrors.Register(ModuleName, 1143, "Service provider already exists")
	ErrServiceProviderNotFound      = sdkerrors.Register(ModuleName, 1144, "Service provider not found")

	ErrSignatoryAlreadyExists = sdkerrors.Register(ModuleName, 1145, "Signatory already exists")

	ErrInvalidStatus                = sdkerrors.Register(ModuleName, 1146, "Invalid status")
	ErrUpgradeModeNotEnabled        = sdkerrors.Register(ModuleName, 1147, "Enclave upgrade mode not enabled")
	ErrIntervalPublicKeyIDNotExists = sdkerrors.Register(ModuleName, 1148, "Interval public key ID not exists")
)
