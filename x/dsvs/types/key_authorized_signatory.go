package types

import "encoding/binary"

var _ binary.ByteOrder

const (
	// AuthorizedSignatoryKeyPrefix is the prefix to retrieve all AuthorizedSignatory
	AuthorizedSignatoryKeyPrefix = "AuthorizedSignatory/value/"
)

// AuthorizedSignatoryKey returns the store key to retrieve a AuthorizedSignatory from the index fields
func AuthorizedSignatoryKey(
	walletID string,
) []byte {
	var key []byte

	walletIDBytes := []byte(walletID)
	key = append(key, walletIDBytes...)
	key = append(key, []byte("/")...)

	return key
}
