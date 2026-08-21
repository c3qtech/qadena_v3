package main

// WHY A NEW MEASUREMENT CANNOT BE PROMOTED ON A MULTI-PIONEER FLEET.
//
// These are characterization tests: they pin behaviour that already exists, because that behaviour
// deadlocked a live enclave upgrade and nothing in the code said it would.
//
// The promotion loop (validateEnclaveIdentities) asks every addressable pioneer "is this identity
// active?", and each peer answers from getEnclaveIdentity -> trusts(), which consults the TRUSTED
// SET -- not the chain's mirrored EnclaveIdentity row.  Trust is only ever gained by self /
// attested / quorum / bootstrap / handover.  So a measurement that NO RUNNING ENCLAVE HAS YET is in
// nobody's trusted set, every peer truthfully answers inactive, activeCount stays 0, and the loop
// takes the condemn branch -- permanently, since a mirror push can remove trust but never add it.
//
// It has only ever worked through the len(pioneers)==0 self-promotion branch, i.e. on a chain with a
// single addressable pioneer.  On the 4-validator fleet unique049 went straight to `inactive`, and
// the outgoing enclave then refused to hand its sealed keys over:
//
//     But couldn't find an active enclave identity for uniqueID: unique049
//
// TestTrustsIgnoresChainMirror is the load-bearing one: it is the exact step where the asker expects
// a "yes" and gets a "no".

import (
	"testing"

	"cosmossdk.io/store/prefix"
	"github.com/stretchr/testify/require"

	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

// withIdentity sets the package-level measurement globals that isSelf() compares against, and
// restores them.  They are ordinarily //go:embed-ed at build time.
func withIdentity(t *testing.T, uid, sid string) {
	t.Helper()
	oldU, oldS := uniqueID, signerID
	uniqueID, signerID = uid, sid
	t.Cleanup(func() { uniqueID, signerID = oldU, oldS })
}

// writeMirrorRow puts a row in the chain's mirrored EnclaveIdentity store -- the node's opinion,
// which arrives over the socket and is deliberately NOT authoritative for trust.
func writeMirrorRow(t *testing.T, s *qadenaServer, id types.EnclaveIdentity) {
	t.Helper()
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(types.EnclaveIdentityKeyPrefix))
	store.Set(types.EnclaveIdentityKey(id.UniqueID), s.Cdc.MustMarshal(&id))
}

// TestTrustsIgnoresChainMirror is the deadlock, reduced to one assertion.
//
// The chain says unique049 exists -- first as `unvalidated` (freshly registered by governance),
// then even as `active`.  A peer running unique048 still answers "no" both times, which is what
// QueryEnclaveValidateEnclaveIdentity turns into InactiveStatus.
func TestTrustsIgnoresChainMirror(t *testing.T) {
	s := newTestEnclaveServer(t)
	withIdentity(t, "unique048", "signer051")

	for _, mirrored := range []string{types.UnvalidatedStatus, types.ActiveStatus} {
		writeMirrorRow(t, s, types.EnclaveIdentity{
			UniqueID: "unique049", SignerID: "signer051", Status: mirrored,
		})

		// The mirror row is readable -- so this is genuinely about trust, not about the row missing.
		found, _ := s.getEnclaveIdentityByUniqueID("unique049")
		require.True(t, found, "precondition: the mirrored row should exist for status %q", mirrored)

		require.False(t, s.trusts("unique049", "signer051", true),
			"a measurement no enclave is running must not be trusted just because the chain mirror "+
				"says %q -- a mirror push may remove trust but never add it", mirrored)
	}
}

// TestTrustsSelfWithEmptyTrustedSet is the one fact an enclave can establish with no external
// anchor, and the reason a single-pioneer chain can bootstrap at all.
func TestTrustsSelfWithEmptyTrustedSet(t *testing.T) {
	s := newTestEnclaveServer(t)
	withIdentity(t, "unique049", "signer051")

	require.Empty(t, s.sharedEnclaveParams.ActiveEnclaveIdentities, "precondition: nothing trusted yet")
	require.True(t, s.trusts("unique049", "signer051", false),
		"an enclave always trusts its own measurement")
	require.False(t, s.trusts("unique049", "signer999", false),
		"isSelf compares the signer too")
}

// TestTrustsHonoursStatusAndIncludeUnvalidated pins the two-argument meaning relied on by the two
// call sites: verifyRemoteReport passes false (active only), the validation query passes true.
func TestTrustsHonoursStatusAndIncludeUnvalidated(t *testing.T) {
	withIdentity(t, "unique048", "signer051")

	cases := []struct {
		status                string
		activeOnly, orPending bool
	}{
		{types.ActiveStatus, true, true},
		{types.UnvalidatedStatus, false, true},
		{types.InactiveStatus, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.status, func(t *testing.T) {
			s := newTestEnclaveServer(t)
			// Set directly rather than via trustEnclaveIdentity, which would seal and write the
			// params file; the predicate is what is under test.
			s.sharedEnclaveParams.ActiveEnclaveIdentities = []*types.EnclaveIdentity{
				{UniqueID: "unique049", SignerID: "signer051", Status: tc.status},
			}
			require.Equal(t, tc.activeOnly, s.trusts("unique049", "signer051", false))
			require.Equal(t, tc.orPending, s.trusts("unique049", "signer051", true))
			require.False(t, s.trusts("unique049", "signerWRONG", true),
				"a matching uniqueID with the wrong signer must not be trusted")
		})
	}
}

// ---------------------------------------------------------------------------
// Option 1 (2026-08-21): a peer vouches from the chain's governance record as well as from its own
// trusted set.  These are the tests for the fix; the characterization tests above still hold, because
// trusts() itself is unchanged -- what changed is that vouchesForIdentity no longer consults it alone.

// TestVouchesForGovernanceRegisteredCandidate is the step that failed on the fleet.  A peer running
// unique048, which does NOT trust unique049, must now vouch for it because governance registered it.
func TestVouchesForGovernanceRegisteredCandidate(t *testing.T) {
	s := newTestEnclaveServer(t)
	withIdentity(t, "unique048", "signer051")

	writeMirrorRow(t, s, types.EnclaveIdentity{
		UniqueID: "unique049", SignerID: "signer051", Status: types.UnvalidatedStatus,
	})

	require.False(t, s.trusts("unique049", "signer051", true),
		"precondition: we must NOT trust it -- otherwise this proves nothing")

	ok, why := s.vouchesForIdentity("unique049", "signer051")
	require.True(t, ok, "a governance-registered candidate must be vouched for; got %q", why)
	require.Contains(t, why, "governance")
}

// TestVouchesRefusesWithoutGovernanceRecord: attestation-free vouching must still require the
// network to have authorised the measurement.  An unknown measurement gets nothing.
func TestVouchesRefusesWithoutGovernanceRecord(t *testing.T) {
	s := newTestEnclaveServer(t)
	withIdentity(t, "unique048", "signer051")

	ok, why := s.vouchesForIdentity("unique099", "signer051")
	require.False(t, ok, "an unregistered measurement must not be vouched for")
	require.Contains(t, why, "no governance record")
}

// TestVouchesRefusesInactiveRow: condemnation is permanent, so a retired or condemned row must never
// be talked back into a "yes".  This is what stops unique049 from being resurrected.
func TestVouchesRefusesInactiveRow(t *testing.T) {
	s := newTestEnclaveServer(t)
	withIdentity(t, "unique048", "signer051")

	writeMirrorRow(t, s, types.EnclaveIdentity{
		UniqueID: "unique049", SignerID: "signer051", Status: types.InactiveStatus,
	})

	ok, why := s.vouchesForIdentity("unique049", "signer051")
	require.False(t, ok)
	require.Contains(t, why, "inactive")
}

// TestVouchesBindsSignerID: the row must match the identity being asked about, or a registration for
// one signer would vouch for a measurement claiming another.
func TestVouchesRefusesSignerMismatch(t *testing.T) {
	s := newTestEnclaveServer(t)
	withIdentity(t, "unique048", "signer051")

	writeMirrorRow(t, s, types.EnclaveIdentity{
		UniqueID: "unique049", SignerID: "signer051", Status: types.UnvalidatedStatus,
	})

	ok, why := s.vouchesForIdentity("unique049", "signerEVIL")
	require.False(t, ok, "the chain's row names a different signer; that is not a match")
	require.Contains(t, why, "signerID")
}

// TestVouchesStillHonoursTrustedSetWithoutARow: an enclave must keep vouching for what it already
// knows even if the mirrored row is absent -- trust it holds is its own, not the chain's to withdraw
// by omission.
func TestVouchesStillHonoursTrustedSetWithoutARow(t *testing.T) {
	s := newTestEnclaveServer(t)
	withIdentity(t, "unique048", "signer051")

	s.sharedEnclaveParams.ActiveEnclaveIdentities = []*types.EnclaveIdentity{
		{UniqueID: "unique047", SignerID: "signer051", Status: types.ActiveStatus},
	}
	ok, why := s.vouchesForIdentity("unique047", "signer051")
	require.True(t, ok)
	require.Contains(t, why, "trusted set")

	// And self, with nothing on chain and nothing in the set.
	ok, why = s.vouchesForIdentity("unique048", "signer051")
	require.True(t, ok, "an enclave always vouches for its own measurement; got %q", why)
}
