package common

import (
	//	"math/big"
	_ "math/big"
	time "time"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

var GasPrice uint64 = 500000000 // aqdn NOTE THIS IS ALSO in config.yml

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

type Transactions []*TransferFunds

type PublicKeyReq struct {
	FriendlyName    string
	RecoverMnemonic string
	IsEphemeral     bool
	EphAccountIndex uint32
}
