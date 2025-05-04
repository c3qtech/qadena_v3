package types

import "encoding/binary"

var _ binary.ByteOrder

const (
	// WalletKeyPrefix is the prefix to retrieve all Wallet
	WalletKeyPrefix = "Wallet/value/"
)

// WalletKey returns the store key to retrieve a Wallet from the index fields
func WalletKey(
	walletID string,
) []byte {
	var key []byte

	walletIDBytes := []byte(walletID)
	key = append(key, walletIDBytes...)
	key = append(key, []byte("/")...)

	return key
}
