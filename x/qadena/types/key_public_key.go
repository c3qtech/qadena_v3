package types

import "encoding/binary"

var _ binary.ByteOrder

const (
	// PublicKeyKeyPrefix is the prefix to retrieve all PublicKey
	PublicKeyKeyPrefix = "PublicKey/value/"
)

// PublicKeyKey returns the store key to retrieve a PublicKey from the index fields
func PublicKeyKey(
	pubKID string,
	pubKType string,
) []byte {
	var key []byte

	pubKIDBytes := []byte(pubKID)
	key = append(key, pubKIDBytes...)
	key = append(key, []byte("/")...)

	pubKTypeBytes := []byte(pubKType)
	key = append(key, pubKTypeBytes...)
	key = append(key, []byte("/")...)

	return key
}
