package types

const (
	// ParkedExternalAddressKeyPrefix is the prefix to retrieve all ParkedExternalAddress entries.
	//
	// CHAIN-ONLY, DELIBERATELY ABSENT FROM mirroredStores (keeper/enclave_seed_page.go).  The
	// staking hooks park a pioneer row's ExternalIPAddress here while its validator is out of the
	// bonded set; the enclave keys "is this pioneer a share-owner candidate" off the ROW, and that
	// is the whole mechanism -- mirroring the parked value would hand the enclave a second,
	// contradictory answer.  Being unmirrored also keeps the prefix out of the chain/enclave
	// divergence audit, which walks exactly the mirrored set.
	ParkedExternalAddressKeyPrefix = "ParkedExternalAddress/value/"
)

// ParkedExternalAddressKey returns the store key for one parked address.
//
// Keyed by the pioneer row's PubKID -- the pioneer account's bech32 address, which is also the
// validator operator account -- because that is the one identifier the staking hooks can derive
// from a ValAddress without consulting anything mutable (sdk.AccAddress(valAddr) re-encodes the
// same key bytes).  One entry per pioneer: parking is refused while the row is already empty, so
// a value can never be overwritten by a repeated jail cycle.
func ParkedExternalAddressKey(
	pubKID string,
) []byte {
	var key []byte

	pubKIDBytes := []byte(pubKID)
	key = append(key, pubKIDBytes...)
	key = append(key, []byte("/")...)

	return key
}
