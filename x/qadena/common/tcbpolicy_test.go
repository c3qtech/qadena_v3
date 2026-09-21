package common_test

import (
	"testing"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"
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
