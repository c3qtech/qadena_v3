package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

// withSealedParamsDir points the server at a scratch params file, so the seal-on-change path in
// noteExternalAddress actually runs rather than being stubbed out.
func withSealedParamsDir(t *testing.T, s *qadenaServer) string {
	t.Helper()
	dir := t.TempDir()
	s.HomePath = dir
	require.NoError(t, os.MkdirAll(dir+"/enclave_config", 0755))
	// Not persisted across processes, and these tests share one -- reset so the first save of each
	// test writes, exactly as the first save after a restart does.
	lastSavedEnclaveParams = nil
	return dir + "/enclave_config/enclave_params_" + uniqueID + ".json"
}

// resetExtAddrState clears the package-level republish guard between tests.
func resetExtAddrState(t *testing.T) {
	t.Helper()
	extAddrMu.Lock()
	extAddrBroadcast, extAddrGaveUp = "", false
	extAddrMu.Unlock()
	t.Cleanup(func() {
		extAddrMu.Lock()
		extAddrBroadcast, extAddrGaveUp = "", false
		extAddrMu.Unlock()
	})
}

// THE COMPATIBILITY CASE THE ROLLING UPGRADE DEPENDS ON.  A keeper older than the externalAddress
// field leaves it unset, and every command other than `start` leaves it unset too.  Treating that
// as a change would blank the sealed address of a healthy node the moment it was paired with an
// older binary -- which, mid-roll, is every node for a while.
func TestNoteExternalAddressIgnoresEmpty(t *testing.T) {
	s := newTestEnclaveServer(t)
	withSealedParamsDir(t, s)
	resetExtAddrState(t)

	s.setPrivateEnclaveParamsPioneerInfo("pioneer1", "alice", "", "", "")
	s.setPrivateEnclaveParamsPioneerExternalIPAddress("10.0.0.1")

	require.False(t, s.noteExternalAddress(""), "an empty address must not count as a change")
	require.Equal(t, "10.0.0.1", s.getPrivateEnclaveParamsPioneerExternalIPAddress())

	require.False(t, s.noteExternalAddress("   "), "whitespace is not an address either")
	require.Equal(t, "10.0.0.1", s.getPrivateEnclaveParamsPioneerExternalIPAddress())
}

// IDEMPOTENCE MATTERS HERE MORE THAN USUAL: this arrives on every UpdateHeight, so every 11 blocks
// forever.  A version that rewrote the params file each time would reopen the torn-write window --
// which loses SealedTableSharedSecret, and with it every stable-sealed row in both stores -- a few
// thousand times a day for no change at all.
func TestNoteExternalAddressUnchangedDoesNotRewrite(t *testing.T) {
	s := newTestEnclaveServer(t)
	path := withSealedParamsDir(t, s)
	resetExtAddrState(t)
	s.setPrivateEnclaveParamsPioneerInfo("pioneer1", "alice", "", "", "")

	require.True(t, s.noteExternalAddress("10.0.0.1"))
	before, err := os.Stat(path)
	require.NoError(t, err)

	for i := 0; i < 5; i++ {
		require.False(t, s.noteExternalAddress("10.0.0.1"), "re-asserting the same address is not a change")
	}

	after, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, before.ModTime(), after.ModTime(), "re-asserting an unchanged address rewrote the sealed params")
}

// The change itself: a new address is taken and sealed.
func TestNoteExternalAddressChangeIsSealed(t *testing.T) {
	s := newTestEnclaveServer(t)
	path := withSealedParamsDir(t, s)
	resetExtAddrState(t)
	s.setPrivateEnclaveParamsPioneerInfo("pioneer1", "alice", "", "", "")

	require.True(t, s.noteExternalAddress("10.0.0.1"))
	first, err := os.ReadFile(path)
	require.NoError(t, err)

	require.True(t, s.noteExternalAddress("10.0.0.99"))
	require.Equal(t, "10.0.0.99", s.getPrivateEnclaveParamsPioneerExternalIPAddress())

	second, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NotEqual(t, first, second, "a changed address was not written to the sealed params")
}

// planExternalAddressRepublish must stay silent when there is nothing to correct -- this is the
// steady state, hit on every rotation tick for the life of the node.
func TestPlanRepublishSilentWhenRowMatches(t *testing.T) {
	s := newTestEnclaveServer(t)
	withSealedParamsDir(t, s)
	resetExtAddrState(t)

	s.setPrivateEnclaveParamsPioneerInfo("pioneer1", "alice", "", "", "")
	s.setPrivateEnclaveParamsPioneerExternalIPAddress("10.0.0.1")
	s.setIntervalPublicKeyIdNoNotify(types.IntervalPublicKeyID{
		PubKID: "alice", NodeID: "pioneer1", NodeType: types.PioneerNodeType,
		ExternalIPAddress: "10.0.0.1",
	})

	require.Equal(t, "", s.planExternalAddressRepublish(), "a row that already matches must not be republished")
}

// The self-heal: the row disagrees with the seal, so the address is offered for republish.
func TestPlanRepublishWhenRowIsStale(t *testing.T) {
	s := newTestEnclaveServer(t)
	withSealedParamsDir(t, s)
	resetExtAddrState(t)

	s.setPrivateEnclaveParamsPioneerInfo("pioneer1", "alice", "", "", "")
	s.setPrivateEnclaveParamsPioneerExternalIPAddress("10.0.0.99")
	s.setIntervalPublicKeyIdNoNotify(types.IntervalPublicKeyID{
		PubKID: "alice", NodeID: "pioneer1", NodeType: types.PioneerNodeType,
		ExternalIPAddress: "10.0.0.1",
	})

	require.Equal(t, "10.0.0.99", s.planExternalAddressRepublish())
}

// THE PUBLISH LOOP GUARD.  If the broadcast never lands, the row stays stale forever -- and without
// this the node would re-broadcast at every opportunity for the rest of its life.  Offer it once,
// then stop and say why.
func TestPlanRepublishStopsAfterOneFailedAttempt(t *testing.T) {
	s := newTestEnclaveServer(t)
	withSealedParamsDir(t, s)
	resetExtAddrState(t)

	s.setPrivateEnclaveParamsPioneerInfo("pioneer1", "alice", "", "", "")
	s.setPrivateEnclaveParamsPioneerExternalIPAddress("10.0.0.99")
	s.setIntervalPublicKeyIdNoNotify(types.IntervalPublicKeyID{
		PubKID: "alice", NodeID: "pioneer1", NodeType: types.PioneerNodeType,
		ExternalIPAddress: "10.0.0.1",
	})

	require.Equal(t, "10.0.0.99", s.planExternalAddressRepublish(), "the first attempt should be offered")
	// The row never took the new value, so the same comparison is true again.
	require.Equal(t, "", s.planExternalAddressRepublish(), "a republish that did not land must not be retried forever")
	require.Equal(t, "", s.planExternalAddressRepublish())

	// A NEW address re-arms it: whatever went wrong before is no longer what we are publishing.
	require.True(t, s.noteExternalAddress("10.0.0.123"))
	require.Equal(t, "10.0.0.123", s.planExternalAddressRepublish(), "a fresh address must re-arm the guard")
}

// Nothing to correct before the node is initialized, or before its row exists -- publishing that
// row is InitEnclave's and updateIsValidator's job, and this path must not race them.
func TestPlanRepublishSilentBeforeInit(t *testing.T) {
	s := newTestEnclaveServer(t)
	withSealedParamsDir(t, s)
	resetExtAddrState(t)

	require.Equal(t, "", s.planExternalAddressRepublish(), "no sealed address yet")

	s.setPrivateEnclaveParamsPioneerExternalIPAddress("10.0.0.1")
	require.Equal(t, "", s.planExternalAddressRepublish(), "no pioneerID yet")

	s.setPrivateEnclaveParamsPioneerInfo("pioneer1", "alice", "", "", "")
	require.Equal(t, "", s.planExternalAddressRepublish(), "no row on chain yet")
}

// An enclave with no pioneer identity yet must not take the address -- InitEnclave carries one and
// is the only path that can publish the row.  Taking it here would also create the sealed params
// file on a node that has none, purely to record something nothing reads.
func TestNoteExternalAddressIgnoredBeforeInit(t *testing.T) {
	s := newTestEnclaveServer(t)
	path := withSealedParamsDir(t, s)
	resetExtAddrState(t)

	require.False(t, s.noteExternalAddress("10.0.0.1"), "an uninitialized enclave must not take an address")
	require.Equal(t, "", s.getPrivateEnclaveParamsPioneerExternalIPAddress())
	_, err := os.Stat(path)
	require.True(t, os.IsNotExist(err), "sealed params were written for an uninitialized enclave")
}
