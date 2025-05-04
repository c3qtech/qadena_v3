package types

import "encoding/binary"

var _ binary.ByteOrder

const (
	// JarRegulatorKeyPrefix is the prefix to retrieve all JarRegulator
	JarRegulatorKeyPrefix = "JarRegulator/value/"
)

// JarRegulatorKey returns the store key to retrieve a JarRegulator from the index fields
func JarRegulatorKey(
	jarID string,
) []byte {
	var key []byte

	jarIDBytes := []byte(jarID)
	key = append(key, jarIDBytes...)
	key = append(key, []byte("/")...)

	return key
}
