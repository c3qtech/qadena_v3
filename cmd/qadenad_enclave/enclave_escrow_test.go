package main

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func testEscrowParams() escrowedPrivateParams {
	return escrowedPrivateParams{
		PioneerID:                "pioneer1",
		EnclaveArmorPrivK:        "armor",
		EnclavePrivK:             "enclave-privk",
		EnclavePubK:              "enclave-pubk",
		SealedTableSharedSecret:  []byte("0123456789abcdef0123456789abcdef"),
		TrustHeightHighWaterMark: 4242,
		PioneerIsValidator:       true,
	}
}

func TestEscrowRoundTrip(t *testing.T) {
	p := testEscrowParams()
	b, err := sealEscrow(p, "jar1", "jar-privk")
	require.NoError(t, err)

	got, err := openEscrow(b, "pioneer1", "jar1", "jar-privk")
	require.NoError(t, err)
	require.Equal(t, p, *got)
}

// The blob is readable by every enclave holding the jar key, so it must refuse to be read as
// anything but what it is: this pioneer's, under this jar.
func TestEscrowRefusesTheWrongBlob(t *testing.T) {
	b, err := sealEscrow(testEscrowParams(), "jar1", "jar-privk")
	require.NoError(t, err)

	_, err = openEscrow(b, "pioneer2", "jar1", "jar-privk")
	require.ErrorContains(t, err, "belongs to pioneer")

	_, err = openEscrow(b, "pioneer1", "jar2", "jar-privk")
	require.ErrorContains(t, err, "jar")

	_, err = openEscrow(b, "pioneer1", "jar1", "another-jar-privk")
	require.ErrorContains(t, err, "does not decrypt")
}

// The clear header is bound into the AEAD: editing it -- say, to make a stale blob claim the key the
// chain now records -- breaks decryption rather than passing the on-chain comparison.
func TestEscrowHeaderIsAuthenticated(t *testing.T) {
	b, err := sealEscrow(testEscrowParams(), "jar1", "jar-privk")
	require.NoError(t, err)

	var f escrowFile
	require.NoError(t, json.Unmarshal(b, &f))
	f.EnclavePubK = "a-different-pubk"
	edited, err := json.Marshal(f)
	require.NoError(t, err)
	_, err = openEscrow(edited, "pioneer1", "jar1", "jar-privk")
	require.ErrorContains(t, err, "does not decrypt")

	require.NoError(t, json.Unmarshal(b, &f))
	f.Ciphertext[0] ^= 1
	edited, err = json.Marshal(f)
	require.NoError(t, err)
	_, err = openEscrow(edited, "pioneer1", "jar1", "jar-privk")
	require.ErrorContains(t, err, "does not decrypt")
}

func setUpEscrowableParams(s *qadenaServer) {
	p := testEscrowParams()
	s.setPrivateEnclaveParamsPioneerInfo(p.PioneerID, "pioneer1-wallet", "", "", "")
	s.setPrivateEnclaveParamsEnclaveInfo(p.EnclaveArmorPrivK, p.EnclavePrivK, p.EnclavePubK)
	s.setPrivateEnclaveParamsSealedTableSharedSecret(p.SealedTableSharedSecret)
	s.setPrivateEnclaveParamsPioneerIsValidator(true)
	s.advanceTrustHeightHighWaterMark(p.TrustHeightHighWaterMark, 1)
	s.setSharedEnclaveParamsJarInfo("jar1", "jar-pubk", "jar-privk", "jar-armor")
}

// Every sealed write refreshes the escrow, so it is never older than the file it backs up.
func TestSaveEnclaveParamsWritesEscrow(t *testing.T) {
	s := newTestEnclaveServer(t)
	withSealedParamsDir(t, s)
	setUpEscrowableParams(s)

	require.True(t, s.saveEnclaveParams())

	b, err := os.ReadFile(s.escrowPath())
	require.NoError(t, err)
	got, err := openEscrow(b, "pioneer1", "jar1", "jar-privk")
	require.NoError(t, err)
	require.Equal(t, testEscrowParams(), *got)

	// and it follows a later change
	s.advanceTrustHeightHighWaterMark(9000, 1)
	require.True(t, s.saveEnclaveParams())
	b, err = os.ReadFile(s.escrowPath())
	require.NoError(t, err)
	got, err = openEscrow(b, "pioneer1", "jar1", "jar-privk")
	require.NoError(t, err)
	require.Equal(t, int64(9000), got.TrustHeightHighWaterMark)
}

// Nothing to encrypt under yet: no file, and no error.
func TestEscrowSkippedWithoutJarKey(t *testing.T) {
	s := newTestEnclaveServer(t)
	withSealedParamsDir(t, s)
	setUpEscrowableParams(s)
	s.setSharedEnclaveParamsJarInfo("", "", "", "")

	require.True(t, s.saveEnclaveParams())
	_, err := os.Stat(s.escrowPath())
	require.True(t, os.IsNotExist(err))
}

// THE REFUSED-SYNC BUG.  While a sync runs, the paths that persist on change -- trustEnclaveIdentity
// above all -- must not write the keys preInitEnclave just minted; only the sync's own final write
// may.
func TestSyncInProgressHoldsParamsWrites(t *testing.T) {
	s := newTestEnclaveServer(t)
	path := withSealedParamsDir(t, s)
	setUpEscrowableParams(s)

	s.syncInProgress = true
	require.True(t, s.saveEnclaveParams(), "a held write is not a failure")
	require.True(t, s.saveEnclaveParamsIfChanged())
	_, err := os.Stat(path)
	require.True(t, os.IsNotExist(err), "params reached disk while a sync was in progress")
	_, err = os.Stat(s.escrowPath())
	require.True(t, os.IsNotExist(err), "escrow reached disk while a sync was in progress")
	require.False(t, s.paramsPersisted)

	require.True(t, s.writeEnclaveParams(), "the sync's own final write goes through")
	_, err = os.Stat(path)
	require.NoError(t, err)
	require.True(t, s.paramsPersisted)
}
