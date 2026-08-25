package common

// The guardian identity-assertion gate, mirrored out of module params.
//
// WHY THIS FILE EXISTS RATHER THAN A DIRECT params READ AT THE DECISION SITE.  Every other gate in
// this module is mirrored into a small policy value in this package first --
// SuspiciousPolicyFromParams and UpdatePolicyFromParams are the templates -- and the enclave
// converts before it branches.  Keeping to that shape means the decision site reads a named state
// rather than an integer, and the one place that has to know how the wire value maps to behaviour
// is here.
//
// WHAT THE GATE IS FOR.  An institutional guardian's app server resolves identity -> wallet on its
// own side, so the enclave could not check that the human who authenticated had anything to do
// with the wallet being signed.  The assertion lets the enclave resolve the identity itself.  The
// gate exists because that scheme rests on an unproven invariant -- that the hash a guardian
// computes at signing time equals the one issuance produced -- and if that is wrong, enforcing it
// rejects every institutional signature.  Audit proves it against real traffic first.

import (
	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

// SignRecoverKeyAssertionMode is the decoded gate.  Two predicates rather than a raw comparison,
// so a caller cannot accidentally write `mode > 0` and mean something subtly different from
// `mode >= audit`.
type SignRecoverKeyAssertionMode uint32

const (
	SignRecoverKeyAssertionOff     = SignRecoverKeyAssertionMode(types.SignRecoverKeyAssertionOff)
	SignRecoverKeyAssertionAudit   = SignRecoverKeyAssertionMode(types.SignRecoverKeyAssertionAudit)
	SignRecoverKeyAssertionEnforce = SignRecoverKeyAssertionMode(types.SignRecoverKeyAssertionEnforce)
)

// Enabled reports whether the assertion should be resolved and compared at all.
func (m SignRecoverKeyAssertionMode) Enabled() bool { return m != SignRecoverKeyAssertionOff }

// Rejects reports whether a mismatch should fail the signature rather than only be logged.
func (m SignRecoverKeyAssertionMode) Rejects() bool { return m == SignRecoverKeyAssertionEnforce }

// String names the mode for the audit log, which is the entire deliverable of the audit state.
func (m SignRecoverKeyAssertionMode) String() string {
	switch m {
	case SignRecoverKeyAssertionAudit:
		return "audit"
	case SignRecoverKeyAssertionEnforce:
		return "enforce"
	default:
		return "off"
	}
}

// SignRecoverKeyAssertionModeFromParams decodes the gate.
//
// ANYTHING UNRECOGNISED READS AS OFF, which is the same direction the proto3 zero takes and the
// only safe one: a value this build does not understand must not be treated as a licence to start
// rejecting signatures.  types.Params.Validate rejects out-of-range values at the gate -- both at
// genesis and on MsgUpdateParams -- so a stored value should never reach here, and this is the
// backstop for a param written by a newer binary than the one reading it.
func SignRecoverKeyAssertionModeFromParams(p types.Params) SignRecoverKeyAssertionMode {
	switch p.SignRecoverKeyGuardianAssertionMode {
	case types.SignRecoverKeyAssertionAudit:
		return SignRecoverKeyAssertionAudit
	case types.SignRecoverKeyAssertionEnforce:
		return SignRecoverKeyAssertionEnforce
	default:
		return SignRecoverKeyAssertionOff
	}
}
