package main

// This node's own identity must be answerable BEFORE it reaches chain state, without being
// written into the mirrored stores.
//
// The mirrored stores are hashed into an accumulator that startup reconciliation compares against
// the chain's copy, so a row the chain has never seen makes a healthy node look diverged.  A
// joiner's own registration does not commit until well into the chain's history -- on 2026-08-26
// a joiner registered at height 439 while replaying from block 1 -- so seeding its identity into
// the mirror made every restart below that height report ENCLAVE STORES DIVERGED.
//
// These tests pin both halves: the readers answer from params when the mirror is empty, and the
// mirror stays empty.

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

func TestOwnPublicKeyAnsweredFromParamsWhenNotYetOnChain(t *testing.T) {
	s := newTestEnclaveServer(t)
	s.setPrivateEnclaveParamsPioneerInfo("pioneer2", "qadena1ownwallet", "armor", "privk", "pioneer-pubk")
	s.setPrivateEnclaveParamsEnclaveInfo("earmor", "eprivk", "enclave-pubk")

	pk, found := s.getPublicKey("qadena1ownwallet", types.TransactionPubKType)
	require.True(t, found, "this node's own transaction key must resolve before it is on chain")
	require.Equal(t, "pioneer-pubk", pk)

	pk, found = s.getPublicKey("qadena1ownwallet", types.EnclavePubKType)
	require.True(t, found, "this node's own enclave key must resolve before it is on chain")
	require.Equal(t, "enclave-pubk", pk)
}

func TestOtherPublicKeyIsStillAMiss(t *testing.T) {
	s := newTestEnclaveServer(t)
	s.setPrivateEnclaveParamsPioneerInfo("pioneer2", "qadena1ownwallet", "armor", "privk", "pioneer-pubk")

	// The fallback is for THIS node only.  Answering for anyone else would invent chain state.
	_, found := s.getPublicKey("qadena1somebodyelse", types.TransactionPubKType)
	require.False(t, found, "another node's key must not be answered from local params")
}

func TestOwnIntervalRecordAnsweredFromParams(t *testing.T) {
	s := newTestEnclaveServer(t)
	s.setPrivateEnclaveParamsPioneerInfo("pioneer2", "qadena1ownwallet", "armor", "privk", "pioneer-pubk")

	keyID, _, _, found := s.getIntervalPublicKeyId("pioneer2", types.PioneerNodeType)
	require.True(t, found, "this node's own interval record must resolve before it is on chain")
	require.Equal(t, "qadena1ownwallet", keyID)

	keyID, _, found = s.getIntervalPublicKeyIdByPubKID("qadena1ownwallet")
	require.True(t, found, "the by-pubKID form must resolve too")
	require.Equal(t, "qadena1ownwallet", keyID)
}

func TestOwnIdentityIsNotWrittenIntoTheMirroredStores(t *testing.T) {
	// The point of the whole change: the params answer, and the MIRROR stays empty, so the
	// accumulator keeps matching the chain's while this node is still unregistered.
	s := newTestEnclaveServer(t)
	s.setPrivateEnclaveParamsPioneerInfo("pioneer2", "qadena1ownwallet", "armor", "privk", "pioneer-pubk")

	_, found := s.getPublicKey("qadena1ownwallet", types.TransactionPubKType)
	require.True(t, found, "precondition: the params answer")

	require.Empty(t, s.getAllPublicKeys(),
		"answering from params must not populate the mirrored PublicKey store -- a row the chain "+
			"has not seen is exactly what makes reconciliation report a divergence")
}
