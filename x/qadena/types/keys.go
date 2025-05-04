package types

import "strings"

const (
	// ModuleName defines the module name
	ModuleName = "qadena"

	// StoreKey defines the primary module store key
	StoreKey = ModuleName

	// MemStoreKey defines the in-memory store key
	MemStoreKey = "mem_qadena"
)

var (
	ParamsKey = []byte("p_qadena")
)

func KeyPrefix(p string) []byte {
	return []byte(p)
}

const (
	SuspiciousTransactionKey      = "SuspiciousTransaction/value/"
	SuspiciousTransactionCountKey = "SuspiciousTransaction/count/"
)

const (
	QadenaTokenDenom  = "qdn"
	AQadenaTokenDenom = "aqdn"
	USDFiatDenom      = "usd"
	AttoUSDFiatDenom  = "atto-usd"
)

const (
	QadenaRealWallet = -1
)

const (
	WalletTypeUnknown   = 0
	WalletTypeReal      = 1
	WalletTypeEphemeral = 2
	WalletTypeCheckTx   = 3
)

const (
	TransactionWalletType uint32 = 0
	CredentialWalletType  uint32 = 1
)

const (
	PioneerNodeType         = "pioneer"
	JarNodeType             = "jar"
	AnonymizerNodeType      = "anonymizer"
	SSNodeType              = "ss"
	TreasuryNodeType        = "treasury"
	RegulatorNodeType       = "regulator"
	ServiceProviderNodeType = "srv-prv"
)

const (
	IdentityServiceProvider = "identity"
	DSVSServiceProvider     = "dsvs"
	FinanceServiceProvider  = "finance"
	InactiveServiceProvider = "inactive"
)

const (
	ActiveStatus      = "active"
	UnvalidatedStatus = "unvalidated"
	InactiveStatus    = "inactive"
)

const (
	SSNodeID       = "ss"
	TreasuryNodeID = "treasury"
)

const (
	CredentialPubKType  = "credential"
	TransactionPubKType = "transaction"
	EnclavePubKType     = "enclave"
)

const (
	EnclaveKeyringName = "enclave"
	SSKeyringName      = "ss"
)

const (
	PersonalInfoCredentialType           = "personal-info"
	FirstNamePersonalInfoCredentialType  = "first-name-" + PersonalInfoCredentialType
	MiddleNamePersonalInfoCredentialType = "middle-name-" + PersonalInfoCredentialType
	LastNamePersonalInfoCredentialType   = "last-name-" + PersonalInfoCredentialType
	PhoneContactCredentialType           = "phone-contact-info"
	EmailContactCredentialType           = "email-contact-info"
)

const (
	AcceptOption        = "accept-"
	RequireSenderOption = "require-sender-"
)

// sender options
const (
	RequirePasswordSenderOption                     = "require-password"
	AcceptFirstNamePersonalInfoSenderOption         = AcceptOption + FirstNamePersonalInfoCredentialType
	AcceptMiddleNamePersonalInfoSenderOption        = AcceptOption + MiddleNamePersonalInfoCredentialType
	AcceptLastNamePersonalInfoSenderOption          = AcceptOption + LastNamePersonalInfoCredentialType
	RequireSenderFirstNamePersonalInfoSenderOption  = RequireSenderOption + FirstNamePersonalInfoCredentialType
	RequireSenderMiddleNamePersonalInfoSenderOption = RequireSenderOption + MiddleNamePersonalInfoCredentialType
	RequireSenderLastNamePersonalInfoSenderOption   = RequireSenderOption + LastNamePersonalInfoCredentialType
)

const (
	GenderM = "m"
	GenderF = "f"
	GenderN = "n"
)

var GenderArray = [...]string{GenderM, GenderF, GenderN}

func NormalizeGender(g string) string {
	g = strings.ToLower(g)

	if ValidateGender(g) {
		return g
	}

	if g == "male" {
		return GenderM
	} else if g == "female" {
		return GenderF
	} else {
		return GenderN
	}
}

func ValidateGender(g string) bool {
	for i := range GenderArray {
		if GenderArray[i] == g {
			return true
		}
	}
	return false
}

var (
	// PortKey defines the key to store the port ID in store
	PortKey = KeyPrefix("qadenawith-port-")
)
