package main

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	ecies "github.com/ecies/go/v2"
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

// testSSKey returns a fresh SS-interval-style key pair in the formats the enclave uses: the private
// key as 32-byte hex, the public key as base64 of the compressed point.
func testSSKey(t *testing.T) (privK, pubK string) {
	t.Helper()
	k, err := ecies.GenerateKey()
	require.NoError(t, err)
	privK = hex.EncodeToString(k.Bytes())
	pubK, err = derivePubKBase64(privK)
	require.NoError(t, err)
	return privK, pubK
}

func sealAndHeader(t *testing.T, ssPubKID, ssPubK string) (*escrowFile, []byte) {
	t.Helper()
	b, err := sealEscrow(testEscrowParams(), ssPubKID, ssPubK)
	require.NoError(t, err)
	f, err := readEscrowHeader(b, "pioneer1")
	require.NoError(t, err)
	return f, b
}

func TestEscrowRoundTrip(t *testing.T) {
	ssPriv, ssPub := testSSKey(t)
	f, _ := sealAndHeader(t, "ss-key-1", ssPub)
	require.Equal(t, "ss-key-1", f.SSPubKID)

	got, err := openEscrow(f, ssPriv)
	require.NoError(t, err)
	require.Equal(t, testEscrowParams(), *got)
}

// The blob must refuse to be read as anything but what it is: this pioneer's, under this SS key.
func TestEscrowRefusesTheWrongBlob(t *testing.T) {
	_, ssPub := testSSKey(t)
	_, b := sealAndHeader(t, "ss-key-1", ssPub)

	_, err := readEscrowHeader(b, "pioneer2")
	require.ErrorContains(t, err, "belongs to pioneer")

	f, err := readEscrowHeader(b, "pioneer1")
	require.NoError(t, err)
	otherPriv, _ := testSSKey(t)
	_, err = openEscrow(f, otherPriv)
	require.ErrorContains(t, err, "does not match")
}

// The clear header is bound into the AEAD: editing it -- say, to make a stale blob claim the key the
// chain now records -- breaks decryption rather than passing the on-chain comparison.
func TestEscrowHeaderIsAuthenticated(t *testing.T) {
	ssPriv, ssPub := testSSKey(t)
	_, b := sealAndHeader(t, "ss-key-1", ssPub)

	edit := func(mut func(*escrowFile)) *escrowFile {
		var f escrowFile
		require.NoError(t, json.Unmarshal(b, &f))
		mut(&f)
		return &f
	}

	_, err := openEscrow(edit(func(f *escrowFile) { f.EnclavePubK = "a-different-pubk" }), ssPriv)
	require.ErrorContains(t, err, "does not decrypt")

	_, err = openEscrow(edit(func(f *escrowFile) { f.SSPubKID = "ss-key-2" }), ssPriv)
	require.ErrorContains(t, err, "does not decrypt")

	_, err = openEscrow(edit(func(f *escrowFile) { f.Ciphertext[0] ^= 1 }), ssPriv)
	require.ErrorContains(t, err, "does not decrypt")
}

// THE REASON FOR THE SS KEY.  The regulator is to be given the jar private key; nothing about the
// escrow may depend on it.  A node with no jar key at all still escrows, and no jar key opens it.
func TestEscrowDoesNotUseTheJarKey(t *testing.T) {
	s := newTestEnclaveServer(t)
	withSealedParamsDir(t, s)
	setUpEscrowableParams(s)
	s.setSharedEnclaveParamsJarInfo("", "", "", "")

	ssPriv, ssPub := testSSKey(t)
	setEscrowSSKey("ss-key-1", ssPub)
	t.Cleanup(func() { setEscrowSSKey("", "") })

	require.True(t, s.saveEnclaveParams())
	b, err := os.ReadFile(s.escrowPath())
	require.NoError(t, err)
	require.NotContains(t, string(b), "jar", "the escrow must not reference the jar")

	f, err := readEscrowHeader(b, "pioneer1")
	require.NoError(t, err)
	_, err = openEscrow(f, ssPriv)
	require.NoError(t, err)
}

func setUpEscrowableParams(s *qadenaServer) {
	p := testEscrowParams()
	s.setPrivateEnclaveParamsPioneerInfo(p.PioneerID, "pioneer1-wallet", "", "", "")
	s.setPrivateEnclaveParamsEnclaveInfo(p.EnclaveArmorPrivK, p.EnclavePrivK, p.EnclavePubK)
	s.setPrivateEnclaveParamsSealedTableSharedSecret(p.SealedTableSharedSecret)
	s.setPrivateEnclaveParamsPioneerIsValidator(true)
	s.advanceTrustHeightHighWaterMark(p.TrustHeightHighWaterMark, 1)
}

// Every sealed write refreshes the escrow, so it is never older than the file it backs up.
func TestSaveEnclaveParamsWritesEscrow(t *testing.T) {
	s := newTestEnclaveServer(t)
	withSealedParamsDir(t, s)
	setUpEscrowableParams(s)
	ssPriv, ssPub := testSSKey(t)
	setEscrowSSKey("ss-key-1", ssPub)
	t.Cleanup(func() { setEscrowSSKey("", "") })

	require.True(t, s.saveEnclaveParams())
	open := func() *escrowedPrivateParams {
		b, err := os.ReadFile(s.escrowPath())
		require.NoError(t, err)
		f, err := readEscrowHeader(b, "pioneer1")
		require.NoError(t, err)
		p, err := openEscrow(f, ssPriv)
		require.NoError(t, err)
		return p
	}
	require.Equal(t, testEscrowParams(), *open())

	// and it follows a later change
	s.advanceTrustHeightHighWaterMark(9000, 1)
	require.True(t, s.saveEnclaveParams())
	require.Equal(t, int64(9000), open().TrustHeightHighWaterMark)
}

// No SS key known yet: no file and no error.  noteEscrowSSKey writes it once one is.
func TestEscrowSkippedWithoutSSKey(t *testing.T) {
	s := newTestEnclaveServer(t)
	withSealedParamsDir(t, s)
	setUpEscrowableParams(s)
	setEscrowSSKey("", "")

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
	_, ssPub := testSSKey(t)
	setEscrowSSKey("ss-key-1", ssPub)
	t.Cleanup(func() { setEscrowSSKey("", "") })

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

// A restored pioneer appears in its own private-state peer list; asking itself deadlocks the block.
func TestPeerHostNormalises(t *testing.T) {
	for _, in := range []string{"10.0.0.5", "10.0.0.5:26657", "tcp://10.0.0.5:26657", " tcp://10.0.0.5 "} {
		require.Equal(t, "10.0.0.5", peerHost(in), in)
	}
	require.NotEqual(t, peerHost("10.0.0.5"), peerHost("10.0.0.6"))
}

// THE RESTART GAP.  A fresh process must pick up the SS key the escrow on disk uses, so its saves keep
// refreshing it -- and must not adopt an escrow written for another enclave key.
func TestEscrowSSKeySeededFromDiskAtStartup(t *testing.T) {
	s := newTestEnclaveServer(t)
	withSealedParamsDir(t, s)
	setUpEscrowableParams(s)
	_, ssPub := testSSKey(t)
	setEscrowSSKey("ss-key-1", ssPub)
	t.Cleanup(func() { setEscrowSSKey("", "") })
	require.True(t, s.saveEnclaveParams())

	// "restart": the in-memory record is gone
	setEscrowSSKey("", "")
	s.seedEscrowSSKeyFromDisk()
	id, pub := currentEscrowSSKey()
	require.Equal(t, "ss-key-1", id)
	require.Equal(t, ssPub, pub)

	// a later save refreshes it without any SS key lookup
	s.advanceTrustHeightHighWaterMark(7777, 1)
	require.True(t, s.saveEnclaveParams())
	b, err := os.ReadFile(s.escrowPath())
	require.NoError(t, err)
	f, err := readEscrowHeader(b, "pioneer1")
	require.NoError(t, err)
	require.Equal(t, "ss-key-1", f.SSPubKID)

	// an escrow for a different enclave key is not adopted
	setEscrowSSKey("", "")
	s.setPrivateEnclaveParamsEnclaveInfo("armor", "other-privk", "other-pubk")
	s.seedEscrowSSKeyFromDisk()
	id, _ = currentEscrowSSKey()
	require.Equal(t, "", id)
}

// Which SS key the escrow may move to: one other owners can rebuild, and never a weaker one.
func TestEscrowKeyDecision(t *testing.T) {
	s := newTestEnclaveServer(t)
	withSealedParamsDir(t, s)
	setUpEscrowableParams(s) // this node is pioneer1

	own := func(key string, owners ...string) { require.True(t, s.setOwnersAndShare(key, owners, "")) }
	own("solo", "pioneer1")                                     // others 0, need 1
	own("pair", "pioneer1", "pioneer2")                         // others 1, need 1 -> spare 0
	own("four", "pioneer1", "pioneer2", "pioneer3", "pioneer4") // others 3, need 2 -> spare 1
	own("three", "pioneer1", "pioneer2", "pioneer3")            // others 2, need 1 -> spare 1

	move, why := s.escrowKeyDecision("", "solo")
	require.False(t, move, "only this node owns it")
	require.Contains(t, why, "no escrow yet")

	move, why = s.escrowKeyDecision("pair", "solo")
	require.False(t, move)
	require.Contains(t, why, "keeping the escrow on pair")

	move, _ = s.escrowKeyDecision("", "pair")
	require.True(t, move, "first qualifying key")

	move, _ = s.escrowKeyDecision("pair", "four")
	require.True(t, move, "more spare owners")

	move, _ = s.escrowKeyDecision("four", "three")
	require.True(t, move, "equal spare owners: newer owners are fresher")

	move, why = s.escrowKeyDecision("four", "pair")
	require.False(t, move, "fewer spare owners")
	require.Contains(t, why, "0 spare owner(s) against 1")

	move, _ = s.escrowKeyDecision("unknown-key", "pair")
	require.True(t, move, "no record of the current key's owners: take the qualifying one")
}
