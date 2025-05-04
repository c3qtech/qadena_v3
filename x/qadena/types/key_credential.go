package types

import "encoding/binary"

var _ binary.ByteOrder

const (
	// CredentialKeyPrefix is the prefix to retrieve all Credential
	CredentialKeyPrefix = "Credential/value/"
)

// CredentialKey returns the store key to retrieve a Credential from the index fields
func CredentialKey(
	credentialID string,
	credentialType string,
) []byte {
	var key []byte

	credentialIDBytes := []byte(credentialID)
	key = append(key, credentialIDBytes...)
	key = append(key, []byte("/")...)

	credentialTypeBytes := []byte(credentialType)
	key = append(key, credentialTypeBytes...)
	key = append(key, []byte("/")...)

	return key
}
