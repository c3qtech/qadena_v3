package types

import "encoding/binary"

var _ binary.ByteOrder

const (
	// DocumentKeyPrefix is the prefix to retrieve all Document
	DocumentKeyPrefix = "Document/value/"
)

// DocumentKey returns the store key to retrieve a Document from the index fields
func DocumentKey(
	documentID string,
) []byte {
	var key []byte

	documentIDBytes := []byte(documentID)
	key = append(key, documentIDBytes...)
	key = append(key, []byte("/")...)

	return key
}
