package types

import "encoding/binary"

var _ binary.ByteOrder

const (
	// ProtectKeyKeyPrefix is the prefix to retrieve all ProtectKey
	ProtectKeyKeyPrefix = "ProtectKey/value/"
)

// ProtectKeyKey returns the store key to retrieve a ProtectKey from the index fields
func ProtectKeyKey(
	walletID string,
) []byte {
	var key []byte

	walletIDBytes := []byte(walletID)
	key = append(key, walletIDBytes...)
	key = append(key, []byte("/")...)

	return key
}
