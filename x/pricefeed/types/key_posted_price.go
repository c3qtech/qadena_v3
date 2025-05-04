package types

import (
	"encoding/binary"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

var _ binary.ByteOrder

const (
	// PostedPriceKeyPrefix is the prefix to retrieve all PostedPrice
	PostedPriceKeyPrefix = "PostedPrice/value/"
)

// PostedPriceKey returns the store key to retrieve a PostedPrice from the index fields
func PostedPriceKey(
	marketId string,
	oracleAddress sdk.AccAddress,
) []byte {
	var key []byte

	marketIdBytes := []byte(marketId)
	key = append(key, marketIdBytes...)
	key = append(key, []byte("/")...)

	//oracleAddressBytes := []byte(oracleAddress)
	oracleAddressBytes := lengthPrefixWithByte(oracleAddress)
	key = append(key, oracleAddressBytes...)
	key = append(key, []byte("/")...)

	return key
}

// lengthPrefixWithByte returns the input bytes prefixes with one byte containing its length.
// It panics if the input is greater than 255 in length.
func lengthPrefixWithByte(bz []byte) []byte {
	length := len(bz)

	if length > 255 {
		panic("cannot length prefix more than 255 bytes with single byte")
	}

	return append([]byte{byte(length)}, bz...)
}
