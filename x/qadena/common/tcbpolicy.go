package common

import (
	"github.com/edgelesssys/ego/attestation/tcbstatus"
)

// THE TCB ALLOW-LIST LIVES HERE SO THERE IS EXACTLY ONE OF IT.
//
// Two places judge a remote report's TCB status: the chain-side verifier
// (cmd/qadenad/realenclave_helper.go, which decides whether to trust a report carried in a tx) and
// the enclave-side verifier (cmd/qadenad_enclave/enclave.go, which decides whether to hand another
// enclave the sealed-table secret and reconstructed interval keys).  They were separate copies of
// the same switch, and a deny-list bug -- comparing against OutOfDate(1) and missing
// OutOfDateConfigurationNeeded(4) -- was fixed in both by hand.  Divergence between the two is a
// silent trust asymmetry, so they now call this.
//
// THIS IS COMPILE-TIME ON PURPOSE, not a chain param.  The enclave binary's measurement is the hash
// of this code, so relaxing the policy produces a DIFFERENT MRENCLAVE.  A node running a laxer
// attestation policy is therefore a visibly different build that genesis must name, rather than a
// node that looks identical and quietly accepts weaker peers.  A param would be the opposite: one
// governance vote would retroactively loosen every enclave in the fleet with no measurement change.

// AllowOutOfDateTCB admits tcbstatus.OutOfDateConfigurationNeeded.
//
// WHAT IT COSTS.  "Out of date" means the attesting platform's CPUSVN/PCESVN are behind the TCB
// level Intel currently publishes -- i.e. microcode or PSW fixes for known SGX vulnerabilities are
// missing.  Those fixes exist because the attacks do; some past SGX TCB recoveries addressed
// enclave-memory disclosure.  Accepting this status means accepting that the host MAY be able to
// extract what its enclave is protecting, which on this chain is pioneer private key shares.  The
// measurement still proves WHICH code ran.  It no longer strongly proves confidentiality.
//
// WHY IT IS ON.  qfi-mainnet runs on CloudSigma VMs (Xeon Gold 6348, Ice Lake-SP, microcode
// 0xd000389) whose microcode is set by the hypervisor host and cannot be updated from the guest.
// Every one of those machines reports OutOfDateConfigurationNeeded, so with a strict allow-list the
// chain cannot attest at all there.  This is a deliberate, documented trade against a hosting
// constraint -- not an oversight, and not a statement that the status is harmless.
//
// WHEN TO TURN IT OFF.  As soon as the host microcode is updated and the platforms report
// UpToDate/ConfigurationNeeded.  Flipping this to false is a security IMPROVEMENT that changes the
// measurement, so it needs the usual new-build/new-enclave-identity path.
const AllowOutOfDateTCB = true

// AcceptableTCBStatus reports whether a verified remote report's TCB status may be trusted.
//
// It is an ALLOW-list.  A status this code has never heard of is refused, which is the right
// failure mode: the alternative silently admits whatever Intel adds next.
//
// Callers MUST NOT call this on a report that failed verification.  ego returns a zero Report for
// every error other than attestation.ErrTCBLevelInvalid, and a zero Report reads as
// UpToDate(0) -- so asking this question of an unverified report answers "healthy" for a forgery.
// Reject the non-TCB errors first, then call this.
func AcceptableTCBStatus(status tcbstatus.Status) bool {
	switch status {
	case tcbstatus.UpToDate, tcbstatus.ConfigurationNeeded,
		tcbstatus.SWHardeningNeeded, tcbstatus.ConfigurationAndSWHardeningNeeded:
		// The platform needs configuration or software hardening, but its TCB is neither out of
		// date nor revoked.
		return true
	case tcbstatus.OutOfDateConfigurationNeeded:
		return AllowOutOfDateTCB
	default:
		// OutOfDate, Revoked, Unknown, and anything added later.
		return false
	}
}
