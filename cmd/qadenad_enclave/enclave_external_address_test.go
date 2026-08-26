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
	extAddrBroadcast, extAddrGaveUp, extAddrUnpublishedNoted = "", false, false
	extAddrMu.Unlock()
	t.Cleanup(func() {
		extAddrMu.Lock()
		extAddrBroadcast, extAddrGaveUp, extAddrUnpublishedNoted = "", false, false
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

// AN EMPTY ROW IS UNPUBLISHED, NOT STALE, and this path must leave it alone.
//
// SyncEnclave and AddAsValidator both create the pioneer row with an empty address, so every joiner
// starts in this state.  Filling it in from here made a node "addressable" within ~11 blocks of
// starting -- unbonded, unable to propose, and counted by getBondedAddressablePioneers, which sizes
// getThreshold.  Observed on the 2026-08-26 bringup: pioneer3 advertised 192.168.86.52 at zero
// voting power because phase 6 had not run.  First publication belongs to updateIsValidator, under
// IsProposer, and to nothing else.
func TestPlanRepublishWillNotPublishAnEmptyRow(t *testing.T) {
	s := newTestEnclaveServer(t)
	withSealedParamsDir(t, s)
	resetExtAddrState(t)

	s.setPrivateEnclaveParamsPioneerInfo("pioneer3", "carol", "", "", "")
	s.setPrivateEnclaveParamsPioneerExternalIPAddress("10.0.0.52")
	s.setIntervalPublicKeyIdNoNotify(types.IntervalPublicKeyID{
		PubKID: "carol", NodeID: "pioneer3", NodeType: types.PioneerNodeType,
		ExternalIPAddress: "",
	})

	require.Equal(t, "", s.planExternalAddressRepublish(),
		"an unpublished row must not be filled in here -- that would make an unbonded node addressable")

	// And it must not have armed the loop guard: nothing was broadcast, so a LATER genuine
	// republish (after the node bonds, publishes, and then moves) must still be offered.
	extAddrMu.Lock()
	broadcast, gaveUp := extAddrBroadcast, extAddrGaveUp
	extAddrMu.Unlock()
	require.Equal(t, "", broadcast, "declining to publish must not record a broadcast")
	require.False(t, gaveUp, "declining to publish must not trip the give-up guard")
}

// The correction path still works once the row HAS been published: this is the moved-node case the
// republish exists for, and the empty-row guard must not have broken it.
func TestPlanRepublishStillCorrectsAPublishedRow(t *testing.T) {
	s := newTestEnclaveServer(t)
	withSealedParamsDir(t, s)
	resetExtAddrState(t)

	s.setPrivateEnclaveParamsPioneerInfo("pioneer3", "carol", "", "", "")
	s.setPrivateEnclaveParamsPioneerExternalIPAddress("10.0.0.99")
	s.setIntervalPublicKeyIdNoNotify(types.IntervalPublicKeyID{
		PubKID: "carol", NodeID: "pioneer3", NodeType: types.PioneerNodeType,
		ExternalIPAddress: "10.0.0.52",
	})

	require.Equal(t, "10.0.0.99", s.planExternalAddressRepublish(),
		"a node that MOVED after publishing must still correct its row")
}

// ---------------------------------------------------------------------------------------------
// The bootstrap address map.  Covers the three properties that make it safe: fallback only,
// replay only, and dropped on going live.

// The window it exists for: an owner whose chain row is still empty because replay has not reached
// the block where it published.  Without the fallback that owner is simply undiallable.
func TestBootstrapAddressUsedWhileReplayingWhenChainRowIsEmpty(t *testing.T) {
	s := newTestEnclaveServer(t)
	s.setPrivateEnclaveParamsPioneerInfo("pioneer1", "wallet-pioneer1", "", "", "")

	owners := []string{"pioneer1", "pioneer2", "pioneer3"}
	withPioneer(s, "pioneer1", "192.168.0.10")
	withPioneer(s, "pioneer2", "192.168.0.11")
	withPioneer(s, "pioneer3", "") // joined, not yet published in OUR replayed view
	s.setOwnersAndShare("k", owners, aShare())
	s.setBootstrapAddresses(map[string]string{"pioneer3": "192.168.0.12"})

	withChainPosition(t, 100, false) // replaying

	job, ok := s.planSSReconstruct("k")
	require.True(t, ok)
	require.Equal(t, "tcp://192.168.0.12:26657", job.nodes["pioneer3"],
		"an owner with no chain row yet must be reachable via the seed's bootstrap address")
}

// FALLBACK ONLY.  A bootstrap entry must never displace an address the chain already knows --
// otherwise a seed could redirect traffic away from a node that is publishing correctly.
func TestBootstrapAddressNeverOverridesTheChainRow(t *testing.T) {
	s := newTestEnclaveServer(t)
	s.setPrivateEnclaveParamsPioneerInfo("pioneer1", "wallet-pioneer1", "", "", "")

	owners := []string{"pioneer1", "pioneer2"}
	withPioneer(s, "pioneer1", "192.168.0.10")
	withPioneer(s, "pioneer2", "192.168.0.11") // the chain HAS an address
	s.setOwnersAndShare("k", owners, aShare())
	s.setBootstrapAddresses(map[string]string{"pioneer2": "10.6.6.6"}) // a different one

	withChainPosition(t, 100, false)

	job, ok := s.planSSReconstruct("k")
	require.True(t, ok)
	require.Equal(t, "tcp://192.168.0.11:26657", job.nodes["pioneer2"],
		"the chain row wins; the bootstrap map may only fill a gap")
}

// REPLAY ONLY.  Once live the mirrored rows are current, so an empty one means the peer really has
// not published -- which must stay visible rather than being papered over by a stale seed answer.
func TestBootstrapAddressNotUsedWhenLive(t *testing.T) {
	s := newTestEnclaveServer(t)
	s.setPrivateEnclaveParamsPioneerInfo("pioneer1", "wallet-pioneer1", "", "", "")

	owners := []string{"pioneer1", "pioneer2"}
	withPioneer(s, "pioneer1", "192.168.0.10")
	withPioneer(s, "pioneer2", "")
	s.setOwnersAndShare("k", owners, aShare())
	s.setBootstrapAddresses(map[string]string{"pioneer2": "192.168.0.12"})

	withChainPosition(t, 100, true) // LIVE

	job, ok := s.planSSReconstruct("k")
	require.True(t, ok)
	require.NotContains(t, job.nodes, "pioneer2",
		"while live an empty chain row means NOT PUBLISHED, and must not be masked")
}

// DISCARDED.  The map has a hard edge, not a fading one.
func TestDropBootstrapAddressesClearsThem(t *testing.T) {
	s := newTestEnclaveServer(t)
	s.setBootstrapAddresses(map[string]string{"pioneer2": "192.168.0.11", "pioneer3": "192.168.0.12"})

	got, ok := s.getBootstrapAddress("pioneer2")
	require.True(t, ok)
	require.Equal(t, "192.168.0.11", got)

	s.dropBootstrapAddresses()

	_, ok = s.getBootstrapAddress("pioneer2")
	require.False(t, ok, "going live must leave nothing behind")
	_, ok = s.getBootstrapAddress("pioneer3")
	require.False(t, ok)

	// Idempotent: the transition can fire again after a restart with nothing left to do.
	s.dropBootstrapAddresses()
}

// A seed too old to send them leaves the joiner exactly as it was before this existed.
func TestBootstrapAddressesAbsentIsHarmless(t *testing.T) {
	s := newTestEnclaveServer(t)
	s.setBootstrapAddresses(map[string]string{})
	_, ok := s.getBootstrapAddress("pioneer2")
	require.False(t, ok)
}

// THE SECTION MUST BE READABLE BY THE TOOL THAT EXISTS TO READ IT.  The values are stored as
// EnclaveStoreString like every other table in the secrets DB; storing raw bytes built fine and
// round-tripped fine through get/set, and would have handed exportSecretsTable garbage -- a section
// that exists but lies is worse than one that is missing.
func TestBootstrapAddressesAreExportable(t *testing.T) {
	s := newTestEnclaveServer(t)
	s.setBootstrapAddresses(map[string]string{
		"pioneer2": "192.168.0.11",
		"pioneer3": "192.168.0.12",
	})

	got := s.exportSecretsTable(EnclaveBootstrapAddressesKeyPrefix)
	require.Equal(t, map[string]string{
		"pioneer2": "192.168.0.11",
		"pioneer3": "192.168.0.12",
	}, got)

	// And an empty section is the CORRECT answer on a live node, not a missing one.
	s.dropBootstrapAddresses()
	require.Empty(t, s.exportSecretsTable(EnclaveBootstrapAddressesKeyPrefix))
}
