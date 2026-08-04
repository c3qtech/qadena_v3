package types

import "encoding/binary"

var _ binary.ByteOrder

const (
	// BankSendWhitelistKeyPrefix is the prefix to retrieve all BankSendWhitelist
	BankSendWhitelistKeyPrefix = "BankSendWhitelist/value/"
)

// BankSendWhitelistKey returns the store key for one whitelisted address.
//
// Keyed by address rather than held as a list so the bank send restriction, which runs on every
// account-to-account transfer, does one point lookup instead of scanning.
func BankSendWhitelistKey(
	address string,
) []byte {
	var key []byte

	addressBytes := []byte(address)
	key = append(key, addressBytes...)
	key = append(key, []byte("/")...)

	return key
}
