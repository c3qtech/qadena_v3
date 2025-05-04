package types

import "encoding/binary"

var _ binary.ByteOrder

const (
	// DocumentHashKeyPrefix is the prefix to retrieve all DocumentHash
	DocumentHashKeyPrefix = "DocumentHash/value/"
)

// DocumentHashKey returns the store key to retrieve a DocumentHash from the index fields
func DocumentHashKey(
	hash string,
) []byte {
	var key []byte

	hashBytes := []byte(hash)
	key = append(key, hashBytes...)
	key = append(key, []byte("/")...)

	return key
}
