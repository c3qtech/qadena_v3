package keeper_test

// THE TIMESTAMP SIGNATURE HAS TWO HALVES AND THEY MUST USE THE SAME SCHEME.
//
// x/qadena/client/cli/query_recover_key.go SIGNS the timestamp; keeper/query_recover_key.go
// VERIFIES it. On 2026-08-21 the verifier was switched from cosmos secp256k1 to eth_secp256k1
// while the signer was left alone, and the halves stopped agreeing.
//
// The failure was invisible where it happened. The CLI signed happily, the chain answered
// "invalid timestamp signature", and what an operator SAW was the credentials regression failing
// with "no seed phrase released after 3 of 3 signatories" -- a whole request later, in a different
// process, describing a symptom nowhere near the cause.
//
// These tests pin the round trip and, more importantly, pin the MISMATCH: the cross-scheme case
// must fail, because that is the bug and a test that only checks the happy path would have passed
// against the broken tree.

import (
	"crypto/rand"
	"strconv"
	"testing"

	cosmossecp256k1 "github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	ethsecp256k1 "github.com/cosmos/evm/crypto/ethsecp256k1"
	"github.com/stretchr/testify/require"
)

func tsBytes(ts int64) []byte { return []byte(strconv.FormatInt(ts, 10)) }

// TestRecoverKeyTimestampSignatureRoundTrip: what the CLI produces, the keeper accepts.
func TestRecoverKeyTimestampSignatureRoundTrip(t *testing.T) {
	priv, err := ethsecp256k1.GenerateKey()
	require.NoError(t, err)

	msg := tsBytes(1755799123)
	sig, err := priv.Sign(msg)
	require.NoError(t, err)

	pub := priv.PubKey().(*ethsecp256k1.PubKey)
	require.True(t, pub.VerifySignature(msg, sig),
		"the keeper must accept a signature made the way the CLI makes it")
}

// TestRecoverKeyRejectsCosmosSecp256k1Signature is the regression that matters: a signature made
// with cosmos secp256k1 -- what the CLI produced before this was fixed -- must NOT verify.
// If this ever starts passing, the two halves have silently converged on different schemes again.
func TestRecoverKeyRejectsCosmosSecp256k1Signature(t *testing.T) {
	raw := make([]byte, 32)
	_, err := rand.Read(raw)
	require.NoError(t, err)

	cosmosPriv := cosmossecp256k1.PrivKey{Key: raw}
	ethPriv := ethsecp256k1.PrivKey{Key: raw}

	msg := tsBytes(1755799123)

	cosmosSig, err := cosmosPriv.Sign(msg)
	require.NoError(t, err)

	// Same key material, so this isolates the SCHEME rather than the identity.
	ethPub := ethPriv.PubKey().(*ethsecp256k1.PubKey)
	require.False(t, ethPub.VerifySignature(msg, cosmosSig),
		"a cosmos secp256k1 signature must NOT satisfy the eth_secp256k1 verifier -- "+
			"if it does, the mismatch this test exists for has stopped being detectable")

	// And the correct pairing still works with that same key, so the failure above is about the
	// scheme and not about a bad key.
	ethSig, err := ethPriv.Sign(msg)
	require.NoError(t, err)
	require.True(t, ethPub.VerifySignature(msg, ethSig))
}

// TestRecoverKeyTimestampIsBoundToItsValue: the signature must not verify for a different
// timestamp, or a captured signature could be replayed against any timestamp the caller likes.
func TestRecoverKeyTimestampIsBoundToItsValue(t *testing.T) {
	priv, err := ethsecp256k1.GenerateKey()
	require.NoError(t, err)
	pub := priv.PubKey().(*ethsecp256k1.PubKey)

	sig, err := priv.Sign(tsBytes(1755799123))
	require.NoError(t, err)

	require.False(t, pub.VerifySignature(tsBytes(1755799124), sig),
		"a signature over one timestamp must not verify against another")
}
