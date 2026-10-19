package main

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func valueSealServer(t *testing.T) *qadenaServer {
	t.Helper()
	s := newTestEnclaveServer(t)
	s.setPrivateEnclaveParamsSealedTableSharedSecret([]byte("0123456789abcdef0123456789abcdef"))
	return s
}

func TestValueSealRoundTrip(t *testing.T) {
	s := valueSealServer(t)
	plain := []byte("a secret row value")

	sealed := s.MustSeal(plain)
	require.NotContains(t, string(sealed), "a secret row value", "the value is stored in the clear")
	require.True(t, bytes.HasPrefix(sealed, []byte(valueSealMagic)), "sealed values must carry the format tag")
	require.Equal(t, plain, s.MustUnseal(sealed))
}

// A FRESH NONCE EVERY CALL.  Two existing properties depend on this: saveEnclaveParamsIfChanged
// compares plaintext rather than ciphertext, and the enclave store cannot be consensus state
// because its bytes differ per node.
func TestValueSealIsNondeterministic(t *testing.T) {
	s := valueSealServer(t)
	plain := []byte("same input")
	a, b := s.MustSeal(plain), s.MustSeal(plain)
	require.NotEqual(t, a, b, "two seals of identical content must differ")
	require.Equal(t, plain, s.MustUnseal(a))
	require.Equal(t, plain, s.MustUnseal(b))
}

func TestValueSealRefusesTamperingAndTheWrongSecret(t *testing.T) {
	s := valueSealServer(t)
	sealed := s.MustSeal([]byte("a secret row value"))

	bad := append([]byte(nil), sealed...)
	bad[len(bad)-1] ^= 1
	_, err := s.tryUnseal(bad)
	require.Error(t, err, "a flipped ciphertext bit must not authenticate")

	// A different node's secret must not open it -- this is what keeps rows node-local.
	s.setPrivateEnclaveParamsSealedTableSharedSecret([]byte("ffffffffffffffffffffffffffffffff"))
	_, err = s.tryUnseal(sealed)
	require.Error(t, err, "another node's SealedTableSharedSecret must not open the row")
}

// THE RETIRED FORMAT IS REFUSED, NOT GUESSED AT.  A product-key blob has no magic; accepting it
// would silently re-open the exposure this change exists to close.
func TestValueSealRefusesUntaggedLegacyBytes(t *testing.T) {
	s := valueSealServer(t)
	_, err := s.tryUnseal([]byte("signer051{\"legacy\":true}"))
	require.ErrorContains(t, err, "not in the "+valueSealMagic+" seal format")
	require.Panics(t, func() { s.MustUnseal([]byte("signer051{\"legacy\":true}")) })
}

// Nothing may be sealed before the params are loaded -- deriving a key from an empty secret would
// produce a valid-looking but meaningless one.
func TestValueSealRefusesWithoutTheSecret(t *testing.T) {
	s := newTestEnclaveServer(t)
	s.setPrivateEnclaveParamsSealedTableSharedSecret(nil)
	_, err := s.valueSealKey()
	require.ErrorContains(t, err, "no SealedTableSharedSecret")
	require.Panics(t, func() { s.MustSeal([]byte("x")) })
}

// THE PARAMS FILE IS THE ONE SGX SEAL, AND IT USES THE UNIQUE KEY.  In a debug build that is the
// uniqueID tag rather than the signerID one; on hardware it is MRENCLAVE rather than MRSIGNER.
// Either way a foreign measurement must not be able to open it.
func TestEnclaveParamsAreSealedToTheMeasurement(t *testing.T) {
	s := valueSealServer(t)
	path := withSealedParamsDir(t, s)
	s.setPrivateEnclaveParamsPioneerInfo("pioneer1", "wallet1", "", "", "")
	s.setPrivateEnclaveParamsEnclaveInfo("armor", "epriv", "epub")
	require.True(t, s.writeEnclaveParams())

	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(string(raw), uniqueID),
		"the params file must be sealed to the MEASUREMENT (uniqueID), not the signer")
	require.False(t, strings.HasPrefix(string(raw), signerID),
		"a signerID-sealed params file is readable by any build with the repo key")
}
