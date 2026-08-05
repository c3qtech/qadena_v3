package types

import "encoding/binary"

var _ binary.ByteOrder

const (
	// ScannedContractWhitelistKeyPrefix is the prefix to retrieve all ScannedContractWhitelist
	ScannedContractWhitelistKeyPrefix = "ScannedContractWhitelist/value/"
)

// ScannedContractWhitelistKey returns the store key for one whitelisted party.
//
// Keyed by address rather than held as a list so the bank send restriction, which runs on every
// account-to-account transfer, does one point lookup instead of scanning.
//
// The pinned code ID is deliberately NOT part of the key.  The restriction has to answer "is this
// address listed, and under which code ID" in a single read: keying on the pair would turn a
// migrated contract into a lookup miss indistinguishable from an unlisted address, and those two
// cases need different errors.
func ScannedContractWhitelistKey(
	address string,
) []byte {
	var key []byte

	addressBytes := []byte(address)
	key = append(key, addressBytes...)
	key = append(key, []byte("/")...)

	return key
}
