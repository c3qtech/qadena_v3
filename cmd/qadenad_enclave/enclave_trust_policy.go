package main

import (
	"sync"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"
)

// THE CHAIN'S HALF OF THE TCB POLICY, AND WHY IT CAN ONLY EVER NARROW.
//
// The keeper pushes the effective permitted-status set on UpdateHeight (every 11 blocks).  This
// enclave then INTERSECTS it with the set it was compiled with and uses the result to judge peer
// remote reports -- the decision that gates handing another enclave the sealed-table secret and
// reconstructed interval keys.
//
// THE INTERSECTION IS NOT AN OPTIMISATION, IT IS THE SECURITY BOUNDARY.  Everything arriving on
// UpdateHeight crossed the node process, which is UNMEASURED HOST CODE.  If this value could widen
// what the enclave accepts, the machine's operator would set it to "everything", stand up a peer
// that attests to nothing in particular, and be handed the secrets the enclave exists to keep from
// exactly that person.  Because it can only narrow, a lying host achieves nothing it could not
// achieve by pulling the power cable: making its own enclave refuse peers.
//
// So the direction is asymmetric on purpose, and the asymmetry must survive edits here:
//
//	effective = compiled ∩ pushed    (and c.TCBPolicyFromParams already put the UpToDate floor in)
//
// NOT SEALED, DELIBERATELY.  This is chain-derived and refreshed every few blocks; it describes the
// chain's current opinion, not this enclave's identity.  Putting it in privateEnclaveParams would
// mean rewriting the blob that holds SealedTableSharedSecret -- "every rewrite is a window in which
// a crash leaves it torn" -- several times an hour, to persist something the next UpdateHeight
// supplies for free.  A package-level var with its own mutex, exactly as setChainPosition does with
// the height and live flag from this same RPC.
var (
	trustPolicyMutex sync.RWMutex
	trustPolicySet   c.TCBAllowSet
	trustPolicyKnown bool
)

// setEnclaveTrustPolicy records what the chain says, narrowed by what this build permits.  Reports
// whether the effective set CHANGED, so the caller can log a transition rather than every 11
// blocks -- a policy change is a rare and security-relevant event and should be visible in the log
// when it happens, not buried in a repeating line.
//
// An EMPTY list means "no opinion" and leaves the previous answer in place: an older keeper does
// not send the field at all, and a new enclave paired with one during a rolling upgrade must keep
// using its compiled policy rather than falling to an empty set and refusing every peer.
func setEnclaveTrustPolicy(names []string) (changed bool) {
	if len(names) == 0 {
		return false
	}

	// ONE implementation of the ratchet, shared with the chain-side verifier: it parses the names,
	// drops any this build does not recognise rather than guessing at them, intersects with the
	// compiled set and re-applies the UpToDate floor.
	effective := c.TCBAllowSetFromNames(names)

	trustPolicyMutex.Lock()
	defer trustPolicyMutex.Unlock()
	changed = !trustPolicyKnown || effective.String() != trustPolicySet.String()
	trustPolicySet = effective
	trustPolicyKnown = true
	return changed
}

// currentEnclaveTrustPolicy answers what this enclave currently accepts.
//
// BEFORE THE FIRST PUSH IT IS THE COMPILED SET, which is what this enclave did before the chain had
// any say at all.  That matters at two moments that are easy to miss: the first blocks after a
// start, before any UpdateHeight has landed; and a rolling upgrade where the paired keeper is older
// than this binary and never sends the field.  Failing to the compiled set in both keeps behaviour
// identical to the previous release rather than refusing every peer.
func currentEnclaveTrustPolicy() c.TCBAllowSet {
	trustPolicyMutex.RLock()
	defer trustPolicyMutex.RUnlock()
	if !trustPolicyKnown {
		return c.CompiledTCBAllowSet()
	}
	return trustPolicySet
}
