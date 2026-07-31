package common

import (
	//	"math/big"
	_ "math/big"
	time "time"

	sdk "github.com/cosmos/cosmos-sdk/types"

	math "cosmossdk.io/math"
)

var GasPrice uint64 = 500000000 // aqdn NOTE THIS IS ALSO in config.yml
var GasPriceInAQDN math.LegacyDec = math.LegacyNewDecFromInt(math.NewInt(int64(GasPrice)))

type WalletAmount struct {
	TransactionID            string
	Nonce                    string
	PedersenCommit           PedersenCommit
	Note                     string
	RequiredSenderPIN        string
	RequiredSenderFirstName  string
	RequiredSenderMiddleName string
	RequiredSenderLastName   string
}

// THIS IS PART OF COMPLIANCE PROOF OF CONCEPT
// COMPLIANCE STRUCTS

// encrypted amount
type EAmount struct {
	Nonce      string
	CoinAmount sdk.Coin
}

// encrypted suspicious amounts
type ESuspiciousAmount struct {
	Nonce         string
	USDCoinAmount sdk.Coin
	CoinAmount    sdk.Coin
}

type TransferFunds struct {
	Time time.Time

	SourceWalletID      string
	DestinationWalletID string

	USDCoinAmount sdk.Coin
	CoinAmount    sdk.Coin
}

// TransferFunds above is still the shape passed to createSuspiciousTransaction when a report is
// filed.  The `Transactions` slice that used to accompany it is gone: the rolling window is now
// stored as EncryptableScanTransferHistory in the enclave's KV store rather than as a Go slice in
// process memory.

type PublicKeyReq struct {
	FriendlyName    string
	RecoverMnemonic string
	IsEphemeral     bool
	EphAccountIndex uint32
}
