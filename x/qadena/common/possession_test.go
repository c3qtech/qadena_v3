package common

import (
	"encoding/base64"
	"testing"

	ecies "github.com/ecies/go/v2"
	"github.com/stretchr/testify/require"
)

// The possession proof must verify with the right key, over the right shares, and fail on every
// tampered variant -- this is the whole ACL for a re-share.
func TestPossessionProofRoundTrip(t *testing.T) {
	k, err := ecies.GenerateKey()
	require.NoError(t, err)
	privK := k.Hex()
	pubK := base64.StdEncoding.EncodeToString(k.PublicKey.Bytes(true))

	creator, pubKID, pubKType, sharesJSON := "qadena1creator", "pubkid", "transaction", `[{"pioneerID":"p1"}]`
	digest := PossessionDigest(creator, pubKID, pubKType, sharesJSON)

	sig, err := SignPossession(privK, digest)
	require.NoError(t, err)
	require.True(t, VerifyPossessionSig(pubK, digest, sig), "the honest proof verifies")

	// Wrong key.
	other, err := ecies.GenerateKey()
	require.NoError(t, err)
	otherPubK := base64.StdEncoding.EncodeToString(other.PublicKey.Bytes(true))
	require.False(t, VerifyPossessionSig(otherPubK, digest, sig), "a different key must not verify")

	// Wrong shares (a proof cannot be re-attached to a different owner set).
	otherDigest := PossessionDigest(creator, pubKID, pubKType, `[{"pioneerID":"p1"},{"pioneerID":"p2"}]`)
	require.False(t, VerifyPossessionSig(pubK, otherDigest, sig), "a proof over different shares must not verify")

	// Garbage signature.
	require.False(t, VerifyPossessionSig(pubK, digest, []byte("garbage")))

	// A signature by the wrong key over the correct digest still fails against the real pubK.
	sig2, err := SignPossession(other.Hex(), digest)
	require.NoError(t, err)
	require.False(t, VerifyPossessionSig(pubK, digest, sig2), "sig by the wrong key must not verify")
	require.True(t, VerifyPossessionSig(otherPubK, digest, sig2), "but does verify against its own key")
}

func TestSignPossessionRejectsBadScalar(t *testing.T) {
	_, err := SignPossession("shorthex", []byte("digest"))
	require.Error(t, err)
}

// GenerateSharedSecret must ALWAYS return exactly 32 bytes.
//
// It used to return big.Int.Bytes(), which strips leading zeros, so ~1 in 256 secrets came back
// short -- aes.NewCipher rejects those, and the discarded error turned it into a nil-pointer panic
// inside crypto/cipher.  preInitEnclave mints SealedTableSharedSecret this way, so it bricked
// roughly one enclave initialisation in 263 and presented as random unrelated test failures.
//
// 20k iterations puts the probability of missing a regression at (255/256)^20000, which is nil.
func TestGenerateSharedSecretIsAlwaysAESSized(t *testing.T) {
	for i := 0; i < 20000; i++ {
		s := GenerateSharedSecret()
		if len(s) != 32 {
			t.Fatalf("iteration %d produced a %d-byte secret; aes.NewCipher needs 16/24/32", i, len(s))
		}
	}
}

// The whole point of the fix: a secret from GenerateSharedSecret must seal and unseal cleanly,
// every time, and a BAD secret must produce a returned error rather than a panic.
func TestSharedSecretSealRoundTripAndErrorDiscipline(t *testing.T) {
	for i := 0; i < 2000; i++ {
		secret := GenerateSharedSecret()
		ct, err := SharedSecretNoNonceEncrypt(secret, []byte("stable-key-material"))
		require.NoError(t, err, "iteration %d", i)
		pt, err := SharedSecretNoNonceDecrypt(secret, ct)
		require.NoError(t, err, "iteration %d", i)
		require.Equal(t, "stable-key-material", string(pt))
	}

	// A short secret must ERROR, not panic -- this is what MustSealStable turns into a readable
	// "Could not seal stable" instead of a segfault in crypto/cipher.
	for _, bad := range [][]byte{nil, {}, make([]byte, 8), make([]byte, 31), make([]byte, 33)} {
		require.NotPanics(t, func() {
			_, err := SharedSecretNoNonceEncrypt(bad, []byte("x"))
			require.Error(t, err, "a %d-byte secret must be refused", len(bad))
		}, "a %d-byte secret must not panic", len(bad))
		require.NotPanics(t, func() {
			_, err := SharedSecretNoNonceDecrypt(bad, []byte("x"))
			require.Error(t, err)
		})
	}
}

// Padding must not change the meaning of any secret that already worked: a 32-byte scalar encodes
// identically before and after the fix, so nothing sealed by an existing node becomes unreadable.
func TestPaddingPreservesExistingSecrets(t *testing.T) {
	full := make([]byte, 32)
	for i := range full {
		full[i] = byte(i + 1) // no leading zero -- exactly what Bytes() would have returned
	}
	ct, err := SharedSecretNoNonceEncrypt(full, []byte("sealed-under-the-old-code"))
	require.NoError(t, err)
	pt, err := SharedSecretNoNonceDecrypt(full, ct)
	require.NoError(t, err)
	require.Equal(t, "sealed-under-the-old-code", string(pt),
		"a 32-byte secret must behave identically before and after the fix")
}
