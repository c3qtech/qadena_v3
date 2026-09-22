package main

import (
	"testing"

	"github.com/edgelesssys/ego/attestation/tcbstatus"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"
)

// resetTrustPolicy returns the package state to "nothing pushed yet", which is what a freshly
// started enclave is in.  Package-level state, so tests that leave it set would leak into each
// other -- and into any test that verifies a remote report.
func resetTrustPolicy(t *testing.T) {
	t.Helper()
	trustPolicyMutex.Lock()
	trustPolicySet, trustPolicyKnown = c.TCBAllowSet{}, false
	trustPolicyMutex.Unlock()
	t.Cleanup(func() {
		trustPolicyMutex.Lock()
		trustPolicySet, trustPolicyKnown = c.TCBAllowSet{}, false
		trustPolicyMutex.Unlock()
	})
}

// A HOSTILE HOST MUST NOT BE ABLE TO WIDEN WHAT THIS ENCLAVE ACCEPTS.
//
// This is the reason the push is safe at all.  UpdateHeight arrives from the node process, which is
// unmeasured code under the machine operator's control.  If they could name a status this build
// refuses and have it honoured, they could stand up a peer attesting to a revoked or out-of-date
// platform and be handed the sealed-table secret -- from the very party the enclave exists to keep
// secrets from.
func TestPushedPolicyCannotWidenBeyondTheBuild(t *testing.T) {
	resetTrustPolicy(t)

	compiled := c.CompiledTCBAllowSet()
	// Everything, including what this build refuses -- the lie a malicious host would tell.
	setEnclaveTrustPolicy([]string{
		"UpToDate", "OutOfDate", "Revoked", "ConfigurationNeeded",
		"OutOfDateConfigurationNeeded", "SWHardeningNeeded", "ConfigurationAndSWHardeningNeeded",
	})
	got := currentEnclaveTrustPolicy()

	for _, status := range []tcbstatus.Status{
		tcbstatus.UpToDate, tcbstatus.OutOfDate, tcbstatus.Revoked,
		tcbstatus.ConfigurationNeeded, tcbstatus.OutOfDateConfigurationNeeded,
		tcbstatus.SWHardeningNeeded, tcbstatus.ConfigurationAndSWHardeningNeeded,
	} {
		if got.Permits(status) && !compiled.Permits(status) {
			t.Errorf("a host that asked for everything got %v admitted, which this build refuses -- "+
				"the enclave can now be talked into trusting a peer it was not built to trust",
				tcbstatus.Explain(status))
		}
	}
}

// The host CAN make its own enclave stricter.  That is allowed, and is the point: it is the same
// power the operator already has by switching the machine off.
func TestPushedPolicyCanNarrow(t *testing.T) {
	resetTrustPolicy(t)

	if !c.CompiledTCBAllowSet().Permits(tcbstatus.SWHardeningNeeded) {
		t.Skip("build does not permit SWHardeningNeeded; nothing to narrow")
	}
	setEnclaveTrustPolicy([]string{"UpToDate", "ConfigurationNeeded"})

	if currentEnclaveTrustPolicy().Permits(tcbstatus.SWHardeningNeeded) {
		t.Error("a narrowing push was ignored")
	}
}

// BEFORE ANY PUSH, THE COMPILED SET APPLIES.  Two real moments depend on this: the first blocks
// after a start, before UpdateHeight has fired (it only runs every 11 blocks); and a rolling
// upgrade where the paired keeper predates the field and never sends it.  Falling to an empty set
// in either case would make the node refuse every peer for no stated reason.
func TestUnpushedPolicyIsTheCompiledSet(t *testing.T) {
	resetTrustPolicy(t)

	compiled := c.CompiledTCBAllowSet()
	if got := currentEnclaveTrustPolicy(); got.String() != compiled.String() {
		t.Errorf("before any push the policy should be the compiled set %q, got %q",
			compiled.String(), got.String())
	}
}

// AN EMPTY PUSH MEANS "NO OPINION", NEVER "TRUST NOTHING" -- the rule externalAddress already
// follows on this same RPC.  An older keeper sends no field at all, and the enclave must keep
// working when paired with one.
func TestEmptyPushIsIgnored(t *testing.T) {
	resetTrustPolicy(t)

	if !c.CompiledTCBAllowSet().Permits(tcbstatus.SWHardeningNeeded) {
		t.Skip("build does not permit SWHardeningNeeded; cannot distinguish the states")
	}
	setEnclaveTrustPolicy([]string{"UpToDate"}) // narrow first
	if currentEnclaveTrustPolicy().Permits(tcbstatus.SWHardeningNeeded) {
		t.Fatal("precondition: the narrowing push should have taken effect")
	}

	if changed := setEnclaveTrustPolicy(nil); changed {
		t.Error("an empty push should report no change")
	}
	if currentEnclaveTrustPolicy().Permits(tcbstatus.SWHardeningNeeded) {
		t.Error("an empty push widened the policy back -- it must mean 'no opinion', not 'reset'")
	}
}

// The change flag drives a log line, and a line every 11 blocks would bury the one that matters.
func TestPolicyChangeIsReportedOnceNotEveryPush(t *testing.T) {
	resetTrustPolicy(t)

	if !setEnclaveTrustPolicy([]string{"UpToDate"}) {
		t.Error("the first push must report a change -- it is the transition from 'unknown'")
	}
	if setEnclaveTrustPolicy([]string{"UpToDate"}) {
		t.Error("an identical push must not report a change")
	}
	if !c.CompiledTCBAllowSet().Permits(tcbstatus.ConfigurationNeeded) {
		return
	}
	if !setEnclaveTrustPolicy([]string{"UpToDate", "ConfigurationNeeded"}) {
		t.Error("a genuinely different push must report a change")
	}
}
