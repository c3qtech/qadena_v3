package common_test

import (
	"testing"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"
	"github.com/c3qtech/qadena_v3/x/qadena/types"
	"github.com/edgelesssys/ego/attestation/tcbstatus"
)

// The point of these tests is not that the switch compiles.  It is that the two statuses which have
// actually cost us something stay explicitly decided:
//
//   - Revoked and OutOfDate must never be admitted, whatever AllowOutOfDateTCB is set to.
//   - OutOfDateConfigurationNeeded (4) is the one that slipped past the old `!= OutOfDate(1)`
//     deny-list.  It is admitted now BY CHOICE.  If someone flips AllowOutOfDateTCB to false to
//     tighten the policy, this test must be the thing that tells them qfi-mainnet stops attesting,
//     rather than a fleet that silently fails to come up.
func TestAcceptableTCBStatus(t *testing.T) {
	alwaysOK := []tcbstatus.Status{
		tcbstatus.UpToDate,
		tcbstatus.ConfigurationNeeded,
		tcbstatus.SWHardeningNeeded,
		tcbstatus.ConfigurationAndSWHardeningNeeded,
	}
	for _, s := range alwaysOK {
		if !c.AcceptableTCBStatus(s) {
			t.Errorf("status %v (%d) must be accepted: %s", s, s, tcbstatus.Explain(s))
		}
	}

	neverOK := []tcbstatus.Status{
		tcbstatus.OutOfDate,
		tcbstatus.Revoked,
		tcbstatus.Unknown,
		tcbstatus.Status(99), // a status this build has never heard of
	}
	for _, s := range neverOK {
		if c.AcceptableTCBStatus(s) {
			t.Errorf("status %v (%d) must be refused: %s", s, s, tcbstatus.Explain(s))
		}
	}

	// The deliberate trade, pinned to the constant rather than to a hard-coded expectation, so the
	// test states the coupling instead of breaking when the policy is legitimately tightened.
	if got := c.AcceptableTCBStatus(tcbstatus.OutOfDateConfigurationNeeded); got != c.AllowOutOfDateTCB {
		t.Errorf("OutOfDateConfigurationNeeded accepted=%v, want AllowOutOfDateTCB=%v", got, c.AllowOutOfDateTCB)
	}

	// A zero Report -- what ego returns for every verification error other than ErrTCBLevelInvalid
	// -- reads as UpToDate.  This is not a bug in the allow-list, but it is the reason callers MUST
	// reject the non-TCB errors BEFORE consulting it.  Asserted here so the hazard is visible next
	// to the function rather than only in prose at the call sites.
	var zeroReportStatus tcbstatus.Status
	if !c.AcceptableTCBStatus(zeroReportStatus) {
		t.Fatal("precondition changed: a zero-valued status no longer reads as acceptable; " +
			"re-check whether callers still need to reject verification errors first")
	}
}

// ============================================================================================
// THE RATCHET.  Everything below asserts one property: governance can only SUBTRACT.
// ============================================================================================

// GOVERNANCE CANNOT WIDEN.  This is the security property the design rests on, so it is asserted
// against every status the build refuses, not just a convenient one.  If TCBPolicyFromParams ever
// becomes a union -- which is a one-character mistake -- this fails.
func TestGovernanceCannotWidenBeyondTheBuild(t *testing.T) {
	compiled := c.CompiledTCBAllowSet()

	for _, name := range types.TCBStatusNames() {
		status, ok := types.ParseTCBStatusName(name)
		if !ok {
			t.Fatalf("TCBStatusNames returned %q which ParseTCBStatusName rejects", name)
		}
		if compiled.Permits(status) {
			continue // nothing to widen -- the build already allows it
		}

		// Ask governance for a status the build refuses, and nothing else.
		p := types.Params{EnclaveTrustPolicy: types.EnclaveTrustPolicy{
			PermittedTcbStatuses: []string{name},
		}}
		got := c.TCBPolicyFromParams(p)

		if got.Permits(status) {
			t.Errorf("governance naming %q made it permitted, but the build refuses it -- "+
				"the ratchet has become a union and the measurement no longer bounds what this node accepts", name)
		}
	}
}

// UpToDate SURVIVES ANY NARROWING, including a proposal that names only statuses this build
// refuses.  Without this floor such a proposal empties the set, no node can accept any report, and
// recovery needs a rebuild -- the exact outcome the feature exists to avoid.
func TestUpToDateCannotBeVotedOff(t *testing.T) {
	for _, names := range [][]string{
		{"ConfigurationNeeded"},            // simply omits UpToDate
		{"OutOfDate"},                      // names only what the build refuses
		{"Revoked", "OutOfDate"},           // ditto, several
		{"SWHardeningNeeded", "OutOfDate"}, // a mix
	} {
		p := types.Params{EnclaveTrustPolicy: types.EnclaveTrustPolicy{PermittedTcbStatuses: names}}
		got := c.TCBPolicyFromParams(p)
		if !got.Permits(tcbstatus.UpToDate) {
			t.Errorf("params %v dropped UpToDate; effective set was %q", names, got.String())
		}
	}
}

// AN ABSENT POLICY MUST BEHAVE EXACTLY AS BEFORE THE FIELD EXISTED.  Params bytes predating field
// 29 carry no policy and GetParams on an empty store returns the zero value, so this is the state
// every existing chain is in at the moment of upgrade, and the state at genesis before qadena's
// InitGenesis has run.  If this diverges from the compiled set, shipping the field changes what
// running chains accept.
func TestEmptyPolicyIsUnrestricted(t *testing.T) {
	compiled := c.CompiledTCBAllowSet()
	zero := c.TCBPolicyFromParams(types.Params{}) // proto3 zero: no policy block at all

	for _, name := range types.TCBStatusNames() {
		status, _ := types.ParseTCBStatusName(name)
		if compiled.Permits(status) != zero.Permits(status) {
			t.Errorf("status %q: compiled=%v but zero-params=%v -- an absent policy must be unrestricted",
				name, compiled.Permits(status), zero.Permits(status))
		}
	}
}

// Narrowing WITHIN the compiled set is the whole point, so prove it actually bites: a status the
// build permits can be removed by governance.
func TestGovernanceCanNarrowWithinTheBuild(t *testing.T) {
	compiled := c.CompiledTCBAllowSet()
	if !compiled.Permits(tcbstatus.SWHardeningNeeded) {
		t.Skip("build does not permit SWHardeningNeeded; nothing to narrow")
	}

	p := types.Params{EnclaveTrustPolicy: types.EnclaveTrustPolicy{
		PermittedTcbStatuses: []string{"UpToDate", "ConfigurationNeeded"},
	}}
	got := c.TCBPolicyFromParams(p)

	if got.Permits(tcbstatus.SWHardeningNeeded) {
		t.Error("SWHardeningNeeded survived a proposal that omitted it -- narrowing does not work")
	}
	if !got.Permits(tcbstatus.ConfigurationNeeded) {
		t.Error("ConfigurationNeeded was named and the build permits it, so it must be permitted")
	}
}

// THE OPERATIONAL CASE THIS FEATURE EXISTS FOR: qfi-mainnet ships with AllowOutOfDateTCB so its
// CloudSigma hosts can attest at all.  When the host microcode is finally patched, dropping
// OutOfDateConfigurationNeeded must be a vote, not a rebuild.
func TestOutOfDateConfigurationNeededCanBeVotedOffWithoutARebuild(t *testing.T) {
	if !c.AllowOutOfDateTCB {
		t.Skip("build already refuses OutOfDateConfigurationNeeded")
	}
	if !c.TCBPolicyFromParams(types.Params{}).Permits(tcbstatus.OutOfDateConfigurationNeeded) {
		t.Fatal("precondition: an unrestricted policy should permit it on this build")
	}

	p := types.Params{EnclaveTrustPolicy: types.EnclaveTrustPolicy{
		PermittedTcbStatuses: []string{
			"UpToDate", "ConfigurationNeeded", "SWHardeningNeeded", "ConfigurationAndSWHardeningNeeded",
		},
	}}
	if c.TCBPolicyFromParams(p).Permits(tcbstatus.OutOfDateConfigurationNeeded) {
		t.Error("governance could not tighten away OutOfDateConfigurationNeeded -- " +
			"the one thing this feature is for")
	}
}

// An unparseable name must not widen anything.  Validate rejects these at the gate, so reaching
// TCBPolicyFromParams means a param written by a newer binary; it must be ignored, never guessed.
func TestUnknownNamesAreIgnoredNotGuessed(t *testing.T) {
	p := types.Params{EnclaveTrustPolicy: types.EnclaveTrustPolicy{
		PermittedTcbStatuses: []string{"UpToDate", "SomeStatusFromTheFuture"},
	}}
	got := c.TCBPolicyFromParams(p)

	if !got.Permits(tcbstatus.UpToDate) {
		t.Error("the recognised name was dropped")
	}
	if len(got.Names()) != 1 {
		t.Errorf("effective set should contain only UpToDate, got %q", got.String())
	}
}

// OVER-TIGHTENING MUST BE RECOVERABLE BY VOTE, NOT BY REBUILD.
//
// "Governance can only subtract" is relative to the BUILD, not to time: the compiled set is a
// CEILING, and governance moves freely below it in both directions.  A vote that drops a status can
// be undone by a later vote restoring it, because the compiled set still permits it.
//
// That is the difference between a policy knob and a one-way latch, and it is the reason the
// UpToDate floor exists: a fleet that can always attest can always still govern itself back.  If
// this ever became monotonic, a single over-tight proposal would cost exactly the rebuild this
// feature was built to avoid.
func TestNarrowingIsReversibleByGovernance(t *testing.T) {
	if !c.AllowOutOfDateTCB {
		t.Skip("this build's ceiling excludes OutOfDateConfigurationNeeded; nothing to restore")
	}
	full := []string{
		"UpToDate", "ConfigurationNeeded", "SWHardeningNeeded",
		"ConfigurationAndSWHardeningNeeded", "OutOfDateConfigurationNeeded",
	}
	tightened := full[:4] // the .229 case: everything except OutOfDateConfigurationNeeded

	// 1. tighten
	narrow := c.TCBPolicyFromParams(types.Params{EnclaveTrustPolicy: types.EnclaveTrustPolicy{
		PermittedTcbStatuses: tightened,
	}})
	if narrow.Permits(tcbstatus.OutOfDateConfigurationNeeded) {
		t.Fatal("precondition: the tightening vote should have dropped it")
	}

	// 2. change your mind
	restored := c.TCBPolicyFromParams(types.Params{EnclaveTrustPolicy: types.EnclaveTrustPolicy{
		PermittedTcbStatuses: full,
	}})
	if !restored.Permits(tcbstatus.OutOfDateConfigurationNeeded) {
		t.Error("a later vote could not restore a status the build still permits -- " +
			"narrowing has become a one-way latch, and recovering now needs a rebuild")
	}

	// 3. and clearing the list entirely returns to the build's own policy
	cleared := c.TCBPolicyFromParams(types.Params{})
	if cleared.String() != c.CompiledTCBAllowSet().String() {
		t.Errorf("clearing the policy should return to the compiled set %q, got %q",
			c.CompiledTCBAllowSet().String(), cleared.String())
	}
}
