package types

import "encoding/binary"

var _ binary.ByteOrder

const (
	// IntervalPublicKeyIDKeyPrefix is the prefix to retrieve all IntervalPublicKeyID
	IntervalPublicKeyIDKeyPrefix         = "IntervalPublicKeyID/value/"
	IntervalPublicKeyIDByPubKIDKeyPrefix = "IntervalPublicKeyIDByPubKID/value/"
)

// IntervalPublicKeyIDKey returns the store key to retrieve a IntervalPublicKeyID from the index fields
func IntervalPublicKeyIDKey(
	nodeID string,
	nodeType string,
) []byte {
	var key []byte

	nodeIDBytes := []byte(nodeID)
	key = append(key, nodeIDBytes...)
	key = append(key, []byte("/")...)

	nodeTypeBytes := []byte(nodeType)
	key = append(key, nodeTypeBytes...)
	key = append(key, []byte("/")...)

	return key
}

func IntervalPublicKeyIDByPubKIDKey(
	pubKID string,
) []byte {
	var key []byte

	pubKIDBytes := []byte(pubKID)
	key = append(key, pubKIDBytes...)
	key = append(key, []byte("/")...)

	return key
}
