package types

import "encoding/binary"

var _ binary.ByteOrder

const (
	// NameBindingKeyPrefix is the prefix to retrieve all NameBinding
	NameBindingKeyPrefix = "NameBinding/value/"
)

// NameBindingKey returns the store key to retrieve a NameBinding from the index fields
func NameBindingKey(
	credential string,
	credentialType string,
) []byte {
	var key []byte

	credentialBytes := []byte(credential)
	key = append(key, credentialBytes...)
	key = append(key, []byte("/")...)

	credentialTypeBytes := []byte(credentialType)
	key = append(key, credentialTypeBytes...)
	key = append(key, []byte("/")...)

	return key
}
