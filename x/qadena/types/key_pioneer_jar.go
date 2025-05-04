package types

import "encoding/binary"

var _ binary.ByteOrder

const (
	// PioneerJarKeyPrefix is the prefix to retrieve all PioneerJar
	PioneerJarKeyPrefix = "PioneerJar/value/"
)

// PioneerJarKey returns the store key to retrieve a PioneerJar from the index fields
func PioneerJarKey(
	pioneerID string,
) []byte {
	var key []byte

	pioneerIDBytes := []byte(pioneerID)
	key = append(key, pioneerIDBytes...)
	key = append(key, []byte("/")...)

	return key
}
