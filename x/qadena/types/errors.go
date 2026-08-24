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
	ErrInvalidIdentityOwnerWalletID = sdkerrors.Register(ModuleName, 1149, "Invalid identity owner wallet ID")

	ErrAlreadySignedSignRecoverKey = sdkerrors.Register(ModuleName, 1150, "Already signed recover key")

	ErrNotEnoughSignatoriesQueryGetRecoverKey = sdkerrors.Register(ModuleName, 1151, "Not enough signatories")

	ErrInvalidCreateWallet = sdkerrors.Register(ModuleName, 1152, "Invalid create wallet")

	ErrInvalidPersonalInfo = sdkerrors.Register(ModuleName, 1153, "Invalid personal info")

	ErrCredentialUpdateRejected    = sdkerrors.Register(ModuleName, 1154, "Credential update rejected by change policy")
	ErrCredentialUpdateRateLimited = sdkerrors.Register(ModuleName, 1155, "Credential update rate limited")
	ErrCredentialUpdateNotOwner    = sdkerrors.Register(ModuleName, 1156, "Not the owner of this credential")

	// Returned when a fiat amount cannot be converted because the pricefeed has no usable price for
	// the market.  Operations that need a conversion FAIL CLOSED on this rather than proceeding with
	// a zero rate -- see ExchangeRateToQadena.
	ErrNoPriceForDenom = sdkerrors.Register(ModuleName, 1157, "No pricefeed price available for denomination")

	// Returned when a wallet with no claimed credential tries to send.  The AML reporting threshold
	// is chosen from the sender's residency and citizenship, so a sender with neither has no
	// threshold to be measured against; allowing the transfer under a default would make holding no
	// credential the cheapest way to pick your own limit.  Governed by the
	// allow_transfer_without_ekyc param.
	ErrNoEKYCForTransfer = sdkerrors.Register(ModuleName, 1158, "Sender has no eKYC data; residency or citizenship is required to transfer")

	// A direct bank send that could not be scanned.  Every account-to-account transfer is put
	// through the same AML scan as MsgTransferFunds; a send that cannot be scanned -- because one
	// side is neither a credentialed wallet nor a party on the scanned-contract whitelist -- is
	// refused rather than allowed through unmeasured, since letting it pass would make the scan on
	// the other path pointless.
	ErrBankSendNotScannable = sdkerrors.Register(ModuleName, 1159, "This transfer cannot be AML-scanned; each party must be a wallet with eKYC data or on the scanned-contract whitelist")

	ErrScannedContractExists   = sdkerrors.Register(ModuleName, 1160, "Address is already on the scanned-contract whitelist")
	ErrScannedContractNotFound = sdkerrors.Register(ModuleName, 1161, "Address is not on the scanned-contract whitelist")

	// The pinned code ID no longer matches the code the address is running.
	//
	// Kept distinct from ErrBankSendNotScannable because it means something quite different and
	// needs a different response: the party IS approved, but the code it runs was migrated since
	// approval, so the entry no longer describes what governance reviewed.  Treating a migration as
	// "unknown address" would hide the one case this pinning exists to catch -- a benign contract
	// approved and then migrated into something else.
	ErrScannedContractCodeMismatch = sdkerrors.Register(ModuleName, 1162, "Contract code has changed since it was whitelisted; the whitelist entry no longer applies")

	// A whitelist entry that does not describe the address it names: a wasm contract listed with no
	// pinned code ID, or a non-contract listed with one.  Rejected at proposal time so the mistake
	// surfaces in review rather than as an unexplained refusal later.
	ErrScannedContractCodeIDMismatch = sdkerrors.Register(ModuleName, 1163, "Whitelist codeID does not match the address; use the contract's current code ID, or 0 for a non-contract")

	// A re-share must strictly GROW the owner set: equal or shrunken sets are rejected so a re-share
	// can never destroy a held share by omission, never lower the Shamir threshold, and a replayed
	// re-share fails idempotently instead of applying twice.
	ErrNotOwnerSuperset = sdkerrors.Register(ModuleName, 1164, "re-share owner set must be a proper superset of the current owners")

	// The possession signature did not verify against the STORED row's public key.  Only an enclave
	// that holds the interval private key may re-share it; attestation alone proves the sender runs
	// trusted code, not that it holds this particular key.
	ErrPossessionProofInvalid = sdkerrors.Register(ModuleName, 1165, "re-share possession proof does not verify against the stored public key")

	// A pioneer tried to rewrite an interval-public-key row belonging to a DIFFERENT node.
	//
	// Attestation proves the sender runs trusted code; it does not say which node it is, because
	// the attested string is chosen by the sender.  Without this, any node holding an Active
	// measurement could repoint any other pioneer's externalIPAddress -- an eclipse primitive
	// against share fetch and who-has traffic -- or its PubKID.
	ErrNotRowOwner = sdkerrors.Register(ModuleName, 1166, "an interval public key row may only be updated by the node that owns it")

	// The shared rows (SS, Jar, Regulator) have no per-node owner to compare against, so the
	// weaker-but-real check is that the sender is a registered pioneer at all.
	ErrCreatorNotPioneer = sdkerrors.Register(ModuleName, 1167, "creator is not a registered pioneer")
)
