package types

import "encoding/binary"

var _ binary.ByteOrder

const (
	// EnclaveIdentityKeyPrefix is the prefix to retrieve all EnclaveIdentity
	EnclaveIdentityKeyPrefix = "EnclaveIdentity/value/"
)

// EnclaveIdentityKey returns the store key to retrieve a EnclaveIdentity from the index fields
func EnclaveIdentityKey(
	uniqueID string,
) []byte {
	var key []byte

	uniqueIDBytes := []byte(uniqueID)
	key = append(key, uniqueIDBytes...)
	key = append(key, []byte("/")...)

	return key
}
