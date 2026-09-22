package common

import (
	"sort"
	"strings"

	"github.com/edgelesssys/ego/attestation/tcbstatus"

	"github.com/c3qtech/qadena_v3/x/qadena/types"
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

// AcceptableTCBStatus reports whether a verified remote report's TCB status may be trusted by THIS
// BUILD, before any governance narrowing.
//
// It is an ALLOW-list.  A status this code has never heard of is refused, which is the right
// failure mode: the alternative silently admits whatever Intel adds next.
//
// Callers MUST NOT call this on a report that failed verification.  ego returns a zero Report for
// every error other than attestation.ErrTCBLevelInvalid, and a zero Report reads as
// UpToDate(0) -- so asking this question of an unverified report answers "healthy" for a forgery.
// Reject the non-TCB errors first, then call this.
//
// Callers that HAVE the chain's params should use TCBPolicyFromParams instead; this remains the
// answer for callers with no chain context, and the enclave's fallback before its first push.
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

// TCBAllowSet is an effective allow-list: what the build permits, narrowed by what governance
// permits.  Construct it only through TCBPolicyFromParams or CompiledTCBAllowSet -- a set built any
// other way has not been through the ratchet.
type TCBAllowSet struct {
	allowed map[tcbstatus.Status]struct{}
}

// everyTCBStatus is the domain the ratchet operates over.  Listed rather than derived because
// tcbstatus has no iterator, and a status missing from here is simply never allowed, which is the
// safe direction.
var everyTCBStatus = []tcbstatus.Status{
	tcbstatus.UpToDate,
	tcbstatus.OutOfDate,
	tcbstatus.Revoked,
	tcbstatus.ConfigurationNeeded,
	tcbstatus.OutOfDateConfigurationNeeded,
	tcbstatus.SWHardeningNeeded,
	tcbstatus.ConfigurationAndSWHardeningNeeded,
}

// CompiledTCBAllowSet is what this binary was built to accept -- the ceiling governance narrows
// from, and the value hashed into MRENCLAVE.
func CompiledTCBAllowSet() TCBAllowSet {
	set := TCBAllowSet{allowed: make(map[tcbstatus.Status]struct{}, len(everyTCBStatus))}
	for _, s := range everyTCBStatus {
		if AcceptableTCBStatus(s) {
			set.allowed[s] = struct{}{}
		}
	}
	return set
}

// TCBPolicyFromParams applies governance's narrowing to the compiled set:
//
//	effective = (compiled ∩ governance) ∪ {UpToDate}
//
// INTERSECTION, NEVER UNION.  This is the security property the whole design rests on: a name in
// the param that the build does not already permit has NO effect.  Listing "OutOfDate" here does
// not admit OutOfDate.  If this ever becomes a union, a governance vote can trust anything and the
// measurement stops being an upper bound on what a node accepts -- which is most of what a
// measurement is for.  There is a test asserting exactly this; do not "simplify" it away.
//
// AN EMPTY LIST IS UNRESTRICTED, NOT EMPTY.  Params bytes predating the field carry no policy, and
// GetParams on an empty store returns the zero value, so "no opinion" has to mean "the build's own
// policy" -- otherwise shipping this field would stop every existing chain attesting at the moment
// of upgrade, and at genesis before qadena's InitGenesis has run.
//
// UpToDate SURVIVES ANY NARROWING.  A proposal that omits it (by intent or by typo that Validate
// happened to pass, such as listing only statuses this build does not permit) would otherwise leave
// the fleet unable to accept any report at all -- and recovering from that needs a rebuild, which
// is the one outcome this feature exists to avoid.
func TCBPolicyFromParams(p types.Params) TCBAllowSet {
	return TCBAllowSetFromNames(p.EnclaveTrustPolicy.PermittedTcbStatuses)
}

// TCBAllowSetFromNames is the ratchet itself, and the ONLY implementation of it.
//
// Both callers route through here on purpose.  The chain-side verifier reaches it via
// TCBPolicyFromParams; the enclave reaches it directly, because what arrives on UpdateHeight is a
// list of names rather than a Params.  Two copies of an intersection is precisely how the earlier
// TCB deny-list bug came to need fixing twice, and how a trust asymmetry between the two verifiers
// would be introduced again.
func TCBAllowSetFromNames(names []string) TCBAllowSet {
	compiled := CompiledTCBAllowSet()
	if len(names) == 0 {
		return compiled
	}

	set := TCBAllowSet{allowed: make(map[tcbstatus.Status]struct{}, len(names)+1)}
	for _, name := range names {
		s, ok := types.ParseTCBStatusName(name)
		if !ok {
			// Params.Validate rejects unknown names at the gate, both at genesis and on
			// MsgUpdateParams, so reaching here means a value written by a newer binary than this
			// one.  Skip it rather than guess: an unrecognised name must never widen the set.
			continue
		}
		if _, permitted := compiled.allowed[s]; permitted {
			set.allowed[s] = struct{}{}
		}
	}
	if _, permitted := compiled.allowed[tcbstatus.UpToDate]; permitted {
		set.allowed[tcbstatus.UpToDate] = struct{}{}
	}
	return set
}

// Permits reports whether a verified report carrying this status may be trusted under the effective
// policy.  The same warning as AcceptableTCBStatus applies: never ask this of a report that failed
// verification, because a zero Report reads as UpToDate.
func (s TCBAllowSet) Permits(status tcbstatus.Status) bool {
	_, ok := s.allowed[status]
	return ok
}

// Names lists the effective set, sorted, for logs.  Worth printing once where the policy is
// applied: "which statuses is this node actually accepting" is otherwise only answerable by reading
// the binary and the chain's params together.
func (s TCBAllowSet) Names() []string {
	out := make([]string, 0, len(s.allowed))
	for _, name := range types.TCBStatusNames() {
		if st, ok := types.ParseTCBStatusName(name); ok {
			if _, permitted := s.allowed[st]; permitted {
				out = append(out, name)
			}
		}
	}
	sort.Strings(out)
	return out
}

// String renders the set for a log line.
func (s TCBAllowSet) String() string { return strings.Join(s.Names(), ",") }
