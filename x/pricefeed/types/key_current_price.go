package types

import (
	"encoding/binary"
)

var _ binary.ByteOrder

const (
	// CurrentPriceKeyPrefix is the prefix to retrieve all CurrentPrice
	CurrentPriceKeyPrefix = "CurrentPrice/value/"
)

// CurrentPriceKey returns the store key to retrieve a CurrentPrice from the index fields
func CurrentPriceKey(
	marketId string,
) []byte {
	var key []byte

	marketIdBytes := []byte(marketId)
	key = append(key, marketIdBytes...)

	return key
}
