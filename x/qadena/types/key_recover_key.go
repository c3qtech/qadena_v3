package types

import "encoding/binary"

var _ binary.ByteOrder

const (
	// RecoverKeyKeyPrefix is the prefix to retrieve all RecoverKey
	RecoverKeyKeyPrefix = "RecoverKey/value/"
)

// RecoverKeyKey returns the store key to retrieve a RecoverKey from the index fields
func RecoverKeyKey(
	walletID string,
) []byte {
	var key []byte

	walletIDBytes := []byte(walletID)
	key = append(key, walletIDBytes...)
	key = append(key, []byte("/")...)

	return key
}
