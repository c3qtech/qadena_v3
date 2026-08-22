package main

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

// The cap on SS share splits exists to stop the rotation message growing with the fleet.  These
// tests pin the three properties that make it safe to cap at all, because each one is a way the
// cap could quietly do damage instead:
//
//   1. capping must never UN-SPLIT a key   (getThreshold(3) is 1, and threshold 1 is plaintext)
//   2. owners must stay DISTINCT           (a repeated owner is a repeated Shamir x-coordinate)
//   3. custody must be RANDOM per key      (a fixed custody set is the genesis-era failure, at scale)

// mustSelect exercises the pure half of selection -- the draw -- with no peers live, which is both
// the degraded case (nothing answered) and the shape every property below is about.
func mustSelect(t *testing.T, pioneers []string) []string {
	t.Helper()
	got, err := chooseHolders(effectiveShareCap(), nil, pioneers)
	require.NoError(t, err)
	return got
}

func fleet(n int) []string {
	p := make([]string, 0, n)
	for i := 0; i < n; i++ {
		p = append(p, "pioneer"+strconv.Itoa(i))
	}
	return p
}

// A fleet at or below the cap must come back completely untouched -- the cap is not allowed to
// change behaviour for any fleet small enough not to need it.
// A fleet at or below the cap must come back whole -- and must not be probed at all, since the
// answer cannot change.  randomSubset returns the pool untouched when k covers it.
func TestSelectShareHoldersLeavesSmallFleetsAlone(t *testing.T) {
	for _, n := range []int{1, 2, 3, 4, 5, 19, 20} {
		got, err := randomSubset(fleet(n), effectiveShareCap())
		require.NoError(t, err)
		require.ElementsMatch(t, fleet(n), got,
			"%d pioneers is at or below the cap and must pass through whole", n)
	}
}

func TestSelectShareHoldersCapsLargeFleets(t *testing.T) {
	for _, n := range []int{21, 50, 100, 255, 1000} {
		got := mustSelect(t, fleet(n))
		require.Len(t, got, maxSSShareSplits, "%d pioneers must be capped at maxSSShareSplits", n)
	}
}

// A DUPLICATE OWNER IS A DUPLICATE SHARE.  addSSShare hands shares[i] to pioneers[i], so the same
// pioneer appearing twice would receive two shares and contribute the same x-coordinate twice at
// combine time -- and shamir.Combine has no integrity check to notice.  The wrap-around in
// selectShareHolders is exactly where that could go wrong.
func TestSelectShareHoldersNeverRepeatsAnOwner(t *testing.T) {
	for _, n := range []int{21, 40, 100, 255} {
		// Repeated because the draw is random: one clean pass proves little.
		for trial := 0; trial < 200; trial++ {
			got := mustSelect(t, fleet(n))
			seen := make(map[string]bool, len(got))
			for _, h := range got {
				require.False(t, seen[h], "owner %q selected twice (n=%d trial=%d)", h, n, trial)
				seen[h] = true
			}
			require.Len(t, seen, maxSSShareSplits)
		}
	}
}

// Every selected owner must be a real member of the fleet -- an offset bug that ran off the end
// would produce an owner nobody can dial.
func TestSelectShareHoldersSelectsOnlyRealPioneers(t *testing.T) {
	f := fleet(100)
	member := make(map[string]bool, len(f))
	for _, p := range f {
		member[p] = true
	}
	for trial := 0; trial < 200; trial++ {
		for _, h := range mustSelect(t, f) {
			require.True(t, member[h], "%q is not in the fleet", h)
		}
	}
}

// THE PROPERTY THE CAP EXISTS TO PRESERVE.  A cap that dropped the owner count to three or fewer
// would send getThreshold to 1, and at threshold 1 addSSShare stops splitting and hands every owner
// the whole private key.  That would be a silent downgrade from Shamir to plaintext copies, so it
// is asserted directly rather than inferred from the constant.
func TestCappingNeverUnsplitsAKey(t *testing.T) {
	for _, n := range []int{4, 5, 10, 21, 100, 255, 1000} {
		got := mustSelect(t, fleet(n))
		require.Greater(t, getThreshold(len(got)), 1,
			"a fleet of %d selected %d owners, which getThreshold makes UNSPLIT", n, len(got))
	}
}

// Even a misconfigured cap must not un-split a key.  selectShareHolders clamps to minSSShareSplits
// rather than trusting the value, so setting it to 1 costs redundancy but never confidentiality.
func TestCapBelowTheMinimumIsClamped(t *testing.T) {
	saved := maxSSShareSplits
	defer func() { maxSSShareSplits = saved }()

	for _, bad := range []int{0, 1, 2, 3} {
		maxSSShareSplits = bad
		got := mustSelect(t, fleet(50))
		require.Len(t, got, minSSShareSplits, "cap %d must clamp to minSSShareSplits", bad)
		require.Greater(t, getThreshold(len(got)), 1,
			"cap %d clamped to %d owners, which is still unsplit", bad, len(got))
	}
}

// CUSTODY MUST BE RANDOM PER KEY.  Truncating to the first N would be simpler and would pass every
// test above, while handing every key forever to the same twenty NodeIDs -- the fixed-custody
// failure this system already has at genesis scale.  Two separate draws must therefore differ, and
// across many draws the selection must reach the WHOLE fleet, not a privileged slice of it.
func TestCustodyIsRandomPerKey(t *testing.T) {
	f := fleet(200)

	a := mustSelect(t, f)
	differs := false
	for trial := 0; trial < 50 && !differs; trial++ {
		b := mustSelect(t, f)
		for i := range a {
			if a[i] != b[i] {
				differs = true
				break
			}
		}
	}
	require.True(t, differs, "50 draws all produced an identical owner set -- the selection is not random")

	// Every pioneer must be reachable.  With 20 of 200 drawn uniformly, 400 draws is 8000 slots;
	// a pioneer never appearing would mean the draw cannot reach part of the fleet at all.
	covered := make(map[string]bool)
	for trial := 0; trial < 400; trial++ {
		for _, h := range mustSelect(t, f) {
			covered[h] = true
		}
	}
	require.Len(t, covered, len(f),
		"only %d of %d pioneers were ever selected -- part of the fleet can never own a share", len(covered), len(f))
}

// Uniformity, not merely variety: a biased draw would still pass the test above while quietly
// favouring some pioneers.  Every pioneer's selection rate should sit near cap/fleet.
func TestSelectionIsUniform(t *testing.T) {
	const fleetSize, trials = 100, 3000
	f := fleet(fleetSize)

	count := make(map[string]int, fleetSize)
	for i := 0; i < trials; i++ {
		for _, h := range mustSelect(t, f) {
			count[h]++
		}
	}

	expected := float64(trials*maxSSShareSplits) / float64(fleetSize)
	for _, p := range f {
		got := float64(count[p])
		require.Greater(t, got, expected*0.7, "%s selected %v times, expected ~%v -- draw is biased", p, got, expected)
		require.Less(t, got, expected*1.3, "%s selected %v times, expected ~%v -- draw is biased", p, got, expected)
	}
}

// The caller's slice is the live result of getAddressablePioneers; selecting must not reorder it.
func TestSelectDoesNotMutateTheCallersSlice(t *testing.T) {
	f := fleet(100)
	before := make([]string, len(f))
	copy(before, f)
	for trial := 0; trial < 50; trial++ {
		mustSelect(t, f)
	}
	require.Equal(t, before, f, "selectShareHolders reordered the caller's pioneer slice")
}

// LIVE PEERS FILL THE SET FIRST.  A share on a node that never answers cannot be gathered, so
// everyone that responded must appear before any silent pioneer is considered.
func TestLivePioneersAreAllTakenFirst(t *testing.T) {
	live := []string{"live0", "live1", "live2", "live3", "live4"}
	dark := fleet(80)

	got, err := chooseHolders(maxSSShareSplits, live, dark)
	require.NoError(t, err)
	require.Len(t, got, maxSSShareSplits)
	for _, l := range live {
		require.Contains(t, got, l, "%s answered the probe and must be an owner", l)
	}
}

// THE SET MUST NEVER SHRINK TO THE LIVE COUNT.  Two live peers is two owners, getThreshold(2) is 1,
// and threshold 1 stops splitting and hands every owner the whole key.  Topping up from the silent
// pioneers is what keeps the split alive.
func TestOwnerSetNeverShrinksToTheLiveCount(t *testing.T) {
	dark := fleet(80)
	for liveCount := 0; liveCount < maxSSShareSplits; liveCount++ {
		live := make([]string, 0, liveCount)
		for i := 0; i < liveCount; i++ {
			live = append(live, "live"+strconv.Itoa(i))
		}
		got, err := chooseHolders(maxSSShareSplits, live, dark)
		require.NoError(t, err)
		require.Len(t, got, maxSSShareSplits, "%d live peers must still yield a full owner set", liveCount)
		require.Greater(t, getThreshold(len(got)), 1,
			"%d live peers produced an UNSPLIT key", liveCount)
	}
}

// Top-up must not duplicate a live peer, and must not repeat within itself -- either would be a
// repeated Shamir x-coordinate.
func TestTopUpNeverDuplicatesAnOwner(t *testing.T) {
	live := []string{"live0", "live1", "live2"}
	dark := fleet(80)
	for trial := 0; trial < 200; trial++ {
		got, err := chooseHolders(maxSSShareSplits, live, dark)
		require.NoError(t, err)
		seen := make(map[string]bool, len(got))
		for _, h := range got {
			require.False(t, seen[h], "owner %q selected twice", h)
			seen[h] = true
		}
	}
}

// MORE THAN ENOUGH RESPONDERS MUST STILL BE DRAWN AT RANDOM.  Taking the first `limit` responders
// would rank by latency, and latency is stable -- the same well-connected nodes would own every key,
// which is the fixed-custody failure arriving through a side door.
func TestExcessRespondersAreDrawnAtRandom(t *testing.T) {
	live := fleet(60)

	first, err := chooseHolders(maxSSShareSplits, live, nil)
	require.NoError(t, err)
	require.Len(t, first, maxSSShareSplits)

	differs := false
	for trial := 0; trial < 50 && !differs; trial++ {
		got, err := chooseHolders(maxSSShareSplits, live, nil)
		require.NoError(t, err)
		for i := range got {
			if got[i] != first[i] {
				differs = true
				break
			}
		}
	}
	require.True(t, differs, "50 draws over the same live set were identical -- responders are not drawn at random")
}

// Nothing answered: the draw must degrade to a uniform random subset of the whole fleet, which is
// the behaviour from before liveness was consulted.  A partition must not fail a rotation.
func TestNoRespondersDegradesToARandomDraw(t *testing.T) {
	all := fleet(100)
	got, err := chooseHolders(maxSSShareSplits, nil, all)
	require.NoError(t, err)
	require.Len(t, got, maxSSShareSplits)
	require.Greater(t, getThreshold(len(got)), 1)
}

// TIER ORDER IS THE POINT OF THE TIERS.  A pioneer that was asked and stayed silent is the only one
// we have evidence against, so it must be chosen last -- behind pioneers that were never asked at
// all because the probe cap ran out.
func TestSilentPioneersAreChosenLast(t *testing.T) {
	live := []string{"live0", "live1"}
	unprobed := []string{"unprobed0", "unprobed1", "unprobed2", "unprobed3", "unprobed4",
		"unprobed5", "unprobed6", "unprobed7", "unprobed8", "unprobed9",
		"unprobed10", "unprobed11", "unprobed12", "unprobed13", "unprobed14",
		"unprobed15", "unprobed16", "unprobed17"}
	silent := fleet(50)

	got, err := chooseHolders(maxSSShareSplits, live, unprobed, silent)
	require.NoError(t, err)
	require.Len(t, got, maxSSShareSplits)

	// live(2) + unprobed(18) exactly fills 20, so no silent pioneer may appear.
	for _, h := range got {
		require.NotContains(t, silent, h, "%q was silent and must rank below the unprobed tier", h)
	}
}

// The probe cap must never fall below the split cap -- a probe smaller than the owner set could
// never fill it from live peers alone, which defeats the point of probing.
func TestProbeCapNeverBelowTheSplitCap(t *testing.T) {
	saved := maxSSLivenessProbes
	defer func() { maxSSLivenessProbes = saved }()

	for _, bad := range []int{0, 1, 5, 19} {
		maxSSLivenessProbes = bad
		require.GreaterOrEqual(t, effectiveProbeCap(), effectiveShareCap(),
			"probe cap %d must be raised to at least the split cap", bad)
	}
}

// THE PLAN IS THE RACE FIX, so what it must guarantee is completeness: everything the detached
// rotation goroutine needs from the block store, captured up front, so nothing reads CacheCtx off
// the execution thread.  (The write half of this race was commit 98edd048, the read half for
// reconstruction was 95277e29; ssRotationPlan is the same split applied to rotation.)
func TestPlanSSRotationSnapshotsEverythingTheRotationNeeds(t *testing.T) {
	s := newTestEnclaveServer(t)

	// One fully-formed pioneer: addressable, with an enclave key reachable via its walletID.
	s.setIntervalPublicKeyIdNoNotify(types.IntervalPublicKeyID{
		NodeID:            "pioneer1",
		NodeType:          types.PioneerNodeType,
		PubKID:            "wallet1",
		ExternalIPAddress: "10.0.0.1",
	})
	s.setPublicKeyNoNotify(types.PublicKey{
		PubKID:   "wallet1",
		PubKType: types.EnclavePubKType,
		PubK:     "enclave-pubk-1",
	})

	// Registered but never published an address: getAddressablePioneers excludes it, so the plan
	// must not carry it at all.
	s.setIntervalPublicKeyIdNoNotify(types.IntervalPublicKeyID{
		NodeID:   "pioneer2",
		NodeType: types.PioneerNodeType,
		PubKID:   "wallet2",
	})

	// Addressable but with no resolvable enclave key: stays in the pioneer set (it is addressable),
	// but the plan records no key for it -- selecting it must fail at share-encryption time, not
	// silently.
	s.setIntervalPublicKeyIdNoNotify(types.IntervalPublicKeyID{
		NodeID:            "pioneer3",
		NodeType:          types.PioneerNodeType,
		PubKID:            "wallet3",
		ExternalIPAddress: "10.0.0.3",
	})

	plan := s.planSSRotation()

	require.ElementsMatch(t, []string{"pioneer1", "pioneer3"}, plan.pioneers,
		"addressable means a published address; pioneer2 has none")
	require.Equal(t, "10.0.0.1", plan.ips["pioneer1"])
	require.Equal(t, "10.0.0.3", plan.ips["pioneer3"])
	require.Equal(t, "enclave-pubk-1", plan.enclavePubKs["pioneer1"])

	_, found := plan.enclavePubKs["pioneer3"]
	require.False(t, found, "no enclave key existed for pioneer3, so the plan must not invent one")
	_, found = plan.enclavePubKs["pioneer2"]
	require.False(t, found)
}
