package main

// THE TRUSTED SET: which enclave measurements this enclave will release secrets to.
//
// Kept deliberately separate from the mirrored EnclaveIdentity store, which is the CHAIN's opinion
// and is accumulated and audited against it row for row.  The two normally hold the same thing.
// They differ at exactly one moment, and that moment is the whole reason this file exists.
//
// WHAT WENT WRONG WITHOUT IT.  Trust used to be read straight off the mirrored row's Status, and
// mirrored rows arrive from the node over the socket.  A node with no history to contradict it --
// one whose data/ was wiped, replaying a genesis or a state-sync snapshot it was handed -- can put
// anything in that row.  Genesis is the sharp case: it names the launch enclave `active` with no
// attestation attached and no field able to carry one, so the only defence was SetEnclaveIdentity
// REFUSING every foreign active identity.  That refusal is fatal chain-side (the keeper panics), so
// the moment a chain upgraded its enclave, no new node could ever replay its genesis again:
//
//     [enclave - E]: status must be "inactive" or "unvalidated"
//     panic: codespace qadena code 1146: Invalid status
//
// Storing and trusting were one bit, so the check could not distinguish "record this historical
// fact" from "hand this measurement your jar and regulator private keys".  Splitting them lets the
// store stay byte-identical to the chain -- which the accumulator requires -- while trust follows
// evidence.
//
// HOW TRUST IS GAINED, and there is no other way:
//
//   self        the measurement equals ours.  The one fact an enclave can establish with no
//               external anchor, and what lets a launch node work with nobody to ask.
//   attested    UpdateEnclaveIdentity carrying a remote report from an already-trusted enclave --
//               the existing quorum broadcast (validateEnclaveIdentities -> MsgPioneerUpdate...).
//   quorum      our own validateEnclaveIdentities reaching threshold, which we then broadcast.
//   bootstrap   sync-enclave from a seed running OUR measurement.  Exists so the three above have
//               something to stand on: a fresh enclave's set is {self}, and every quorum query is
//               itself gated on trust, so without this the chain of trust has no root.
//
// HOW TRUST IS LOST:
//
//   a mirror push with Status inactive -- governance or a quorum deactivation flowing in.  Note the
//   asymmetry: a mirror push may REMOVE trust but never add it.  That is what keeps a hostile node
//   unable to do anything except reduce what it is trusted with.
//
// MRSIGNER is deliberately absent from all of this.  It cannot anchor anything here: the signing
// key ships in the repo, so anyone can produce a leaky enclave whose attestation is genuine and
// whose MRSIGNER matches.  Only MRENCLAVE distinguishes builds.

import (
	"strconv"
	"sync"

	"cosmossdk.io/store/prefix"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"
	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

// WHERE THE CHAIN IS, and whether we are watching it happen or replaying it.  Both come from the
// keeper on every UpdateHeight; the enclave cannot derive either for itself, having no trusted clock
// and no view of the chain head.
var (
	chainPositionMutex sync.RWMutex
	chainHeight        int64
	chainIsLive        bool
	chainPositionKnown bool
)

// setChainPosition records the latest block, reporting whether the LIVE/REPLAYING state flipped so
// the caller can log the transition rather than every block.
func setChainPosition(height int64, isLive bool) (transitioned bool) {
	chainPositionMutex.Lock()
	defer chainPositionMutex.Unlock()
	transitioned = !chainPositionKnown || isLive != chainIsLive
	chainHeight = height
	chainIsLive = isLive
	chainPositionKnown = true
	return transitioned
}

func currentChainPosition() (height int64, isLive bool, known bool) {
	chainPositionMutex.RLock()
	defer chainPositionMutex.RUnlock()
	return chainHeight, chainIsLive, chainPositionKnown
}

// attestationMaxAgeBlocks bounds how old a remote report may be and still be treated as evidence
// about NOW.
//
// An SGX quote carries no trusted clock, and DCAP verification consumes collateral with validity
// windows, so re-checking a months-old quote answers a question nobody asked: it may fail for
// reasons that say nothing about the enclave, and passing would still not show the enclave is
// running today.  The chain's height is the one monotonic reference both ends share.
//
// keyUpdateFrequency (555 blocks) is the natural unit here -- it is already the cadence on which
// this system re-derives key material -- and two of them leaves comfortable room for a promotion to
// be broadcast, included and reach every node without ever approaching the bound.
var attestationMaxAgeBlocks = 2 * keyUpdateFrequency

// attestationIsCurrent decides whether a report generated at reportHeight is recent enough to act
// on, and says why when it is not.  Reports from the future are refused too: that is either a
// broken peer or an attempt to buy unlimited lifetime for one quote.
func attestationIsCurrent(reportHeight int64, what string) bool {
	height, isLive, known := currentChainPosition()
	if !known {
		// Before the first UpdateHeight -- sync-enclave runs here, and it verifies the seed by
		// measurement rather than by age.  Nothing to compare against, so do not pretend.
		c.LoggerDebug(logger, "no chain position yet; not judging the age of "+what)
		return true
	}
	if !isLive {
		c.LoggerInfo(logger, "ignoring "+what+" at height "+strconv.FormatInt(reportHeight, 10)+
			": the chain is replaying history (at "+strconv.FormatInt(height, 10)+"), and a historical attestation is not evidence about now")
		return false
	}
	age := height - reportHeight
	if age > attestationMaxAgeBlocks {
		c.LoggerInfo(logger, "ignoring "+what+" attested at height "+strconv.FormatInt(reportHeight, 10)+
			": "+strconv.FormatInt(age, 10)+" blocks old, limit is "+strconv.FormatInt(attestationMaxAgeBlocks, 10))
		return false
	}
	if age < -1 {
		c.LoggerError(logger, "refusing "+what+" attested at height "+strconv.FormatInt(reportHeight, 10)+
			", which is ahead of our height "+strconv.FormatInt(height, 10))
		return false
	}
	c.LoggerDebug(logger, "accepting "+what+" attested at height "+strconv.FormatInt(reportHeight, 10)+", "+strconv.FormatInt(age, 10)+" blocks old")
	return true
}

// isSelf reports whether an identity names this very enclave.  Free of any external anchor: the
// measurement is taken from our own self-report at startup (or the embedded test id in a debug
// build), so no caller can assert it for us.
func isSelf(uid string, sid string) bool {
	return uid == uniqueID && sid == signerID
}

// trustedEnclaveIdentity returns our recorded judgement about a measurement, if we have one.
func (s *qadenaServer) trustedEnclaveIdentity(uid string) (*types.EnclaveIdentity, bool) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	for _, id := range s.sharedEnclaveParams.ActiveEnclaveIdentities {
		if id != nil && id.UniqueID == uid {
			cp := *id
			return &cp, true
		}
	}
	return nil, false
}

// trusts is the predicate the secret-releasing paths hang off, via getEnclaveIdentity.
//
// includeUnvalidated mirrors the old flag: false means "active only" (verifyRemoteReport, the gate
// on every peer-facing handler), true means "active or unvalidated" (the validation query, which
// answers about identities still being decided).
func (s *qadenaServer) trusts(uid string, sid string, includeUnvalidated bool) bool {
	if isSelf(uid, sid) {
		return true
	}
	id, found := s.trustedEnclaveIdentity(uid)
	if !found || id.SignerID != sid {
		return false
	}
	if includeUnvalidated {
		return id.Status != types.InactiveStatus
	}
	return id.Status == types.ActiveStatus
}

// trustEnclaveIdentity records a judgement reached through one of the four routes above.  `why`
// names the route and is logged: a trusted set that grew for an unexplained reason is precisely the
// thing an operator needs to be able to see.
//
// Persisted immediately.  The set lives in the sealed params file, so it survives restarts and a
// wiped data/ -- a node re-joining with its enclave_config intact keeps the trust it had, and only
// a genuinely fresh enclave starts at {self}.
func (s *qadenaServer) trustEnclaveIdentity(in *types.EnclaveIdentity, why string) {
	if in == nil || in.UniqueID == "" {
		return
	}
	changed := func() bool {
		s.mutex.Lock()
		defer s.mutex.Unlock()
		for i, id := range s.sharedEnclaveParams.ActiveEnclaveIdentities {
			if id != nil && id.UniqueID == in.UniqueID {
				if id.SignerID == in.SignerID && id.Status == in.Status {
					return false
				}
				cp := *in
				s.sharedEnclaveParams.ActiveEnclaveIdentities[i] = &cp
				return true
			}
		}
		cp := *in
		s.sharedEnclaveParams.ActiveEnclaveIdentities = append(s.sharedEnclaveParams.ActiveEnclaveIdentities, &cp)
		return true
	}()
	if !changed {
		return
	}
	c.LoggerInfo(logger, "trusting enclave identity "+in.UniqueID+" status "+in.Status+" ("+why+")")
	// Outside the lock: saveEnclaveParams reads both param structs without taking it.
	s.saveEnclaveParamsIfChanged()
}

// untrustEnclaveIdentity drops a measurement from the set.  The only caller is the mirror push
// seeing Status inactive -- see the asymmetry note at the top.
func (s *qadenaServer) untrustEnclaveIdentity(uid string, why string) {
	removed := func() bool {
		s.mutex.Lock()
		defer s.mutex.Unlock()
		for i, id := range s.sharedEnclaveParams.ActiveEnclaveIdentities {
			if id != nil && id.UniqueID == uid {
				s.sharedEnclaveParams.ActiveEnclaveIdentities = append(
					s.sharedEnclaveParams.ActiveEnclaveIdentities[:i],
					s.sharedEnclaveParams.ActiveEnclaveIdentities[i+1:]...)
				return true
			}
		}
		return false
	}()
	if !removed {
		return
	}
	c.LoggerInfo(logger, "no longer trusting enclave identity "+uid+" ("+why+")")
	s.saveEnclaveParamsIfChanged()
}

// activeTrustedEnclaveIdentities is what a seed advertises to a joiner during sync-enclave.
//
// Only entries we consider ACTIVE travel: a joiner should never inherit trust that has already been
// retired, and an unvalidated entry is a judgement still in progress -- the joiner will see it
// resolve through the normal quorum broadcast like everyone else.
func (s *qadenaServer) activeTrustedEnclaveIdentities() []*types.EnclaveIdentity {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	out := make([]*types.EnclaveIdentity, 0, len(s.sharedEnclaveParams.ActiveEnclaveIdentities)+1)

	// OURSELVES FIRST, always, and synthesised rather than stored.  We are the one measurement this
	// enclave can vouch for with authority -- it is the code answering the question -- and a joiner
	// that has just authenticated us as its own build has already accepted exactly that claim.
	//
	// Not kept in the stored set on purpose: bootstrapped() must stay able to tell "I have been
	// given trust by someone" from "I trust myself, as every enclave does", or a fresh joiner would
	// believe itself bootstrapped and start voting in quorums on an empty set.
	out = append(out, &types.EnclaveIdentity{UniqueID: uniqueID, SignerID: signerID, Status: types.ActiveStatus})

	for _, id := range s.sharedEnclaveParams.ActiveEnclaveIdentities {
		if id != nil && id.Status == types.ActiveStatus && id.UniqueID != uniqueID {
			cp := *id
			out = append(out, &cp)
		}
	}
	return out
}

// reconcileTrustOnGoingLive closes the gap that deferring trust changes during replay leaves behind.
//
// While catching up we act on no attestation and honour no deactivation, because replayed history is
// not evidence about now.  That is safe only if nothing is silently DROPPED -- and something can be:
// a promotion that lands while this node is still more than a couple of minutes behind the head is
// replayed, ignored, and never repeated.  The node finishes catch-up missing trust the rest of the
// network has.
//
// It is detectable because the enclave holds both opinions.  The mirrored store is the chain's view,
// replayed to the head; the trusted set is ours, frozen during replay.  Once live, the difference
// between them is exactly what was deferred:
//
//	chain says inactive, we trust it     -> drop it.  A downgrade is always safe to honour, and this
//	                                        is the historical deactivation we skipped.
//	chain says active, we do not trust it -> QUEUE IT FOR VALIDATION.  Not trust it.
//
// The second line is the point.  The mirrored store is untrusted input, so it cannot be the
// authority -- but it is a perfectly good POINTER to what needs verifying.  The identity goes onto
// the unvalidated queue and is resolved the ordinary way: ask peers we already trust, and let their
// attested answers decide.  Genesis may tell us an identity exists; it may not tell us to trust it,
// and the same rule applies to every row the node hands us.
func (s *qadenaServer) reconcileTrustOnGoingLive() {
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(types.EnclaveIdentityKeyPrefix))
	itr := store.Iterator(nil, nil)
	defer itr.Close()

	dropped, queued, agreed := 0, 0, 0
	pending := s.getUnvalidatedEnclaveIdentities()
	alreadyQueued := func(uid string) bool {
		for _, id := range pending.Identity {
			if id != nil && id.UniqueID == uid {
				return true
			}
		}
		return false
	}

	for ; itr.Valid(); itr.Next() {
		var id types.EnclaveIdentity
		s.Cdc.MustUnmarshal(itr.Value(), &id)

		if isSelf(id.UniqueID, id.SignerID) {
			continue
		}
		_, trusted := s.trustedEnclaveIdentity(id.UniqueID)

		switch {
		case id.Status == types.InactiveStatus && trusted:
			s.untrustEnclaveIdentity(id.UniqueID, "reconcile on going live: the chain deactivated it while we were replaying")
			dropped++
		case id.Status == types.ActiveStatus && !trusted:
			if alreadyQueued(id.UniqueID) {
				continue
			}
			cp := id
			pending.Identity = append(pending.Identity, &cp)
			queued++
			c.LoggerInfo(logger, "reconcile on going live: the chain considers "+id.UniqueID+
				" active and we do not trust it -- queued for peer validation, NOT trusted on the chain's word alone")
		default:
			agreed++
		}
	}

	if queued > 0 {
		s.setUnvalidatedEnclaveIdentities(pending)
		// Same short delay a freshly arrived identity gets: a few blocks, so the node is settled
		// before it starts asking peers.
		unvalidatedEnclaveIdentitiesCheckCounter = 2
	}
	c.LoggerInfo(logger, "reconcile on going live: "+strconv.Itoa(agreed)+" identities agreed, "+
		strconv.Itoa(dropped)+" dropped, "+strconv.Itoa(queued)+" queued for validation")
}

// verifySeedIsOurBuild authenticates the OTHER end of the sync-enclave handshake.
//
// A fresh enclave has exactly one anchor it can check without help: itself.  So the rule is that the
// seed must be running our own measurement -- then "a genuine enclave with measurement X" and "X is
// code I already am" collapse into one verifiable statement, and its word on the trusted set is
// worth precisely as much as our own.
//
// checkEnclaveUniqueIDOnly is what makes that possible without consulting the trusted set, which is
// empty at this point by construction.
func (s *qadenaServer) verifySeedIsOurBuild(report []byte, certifiedCiphertext []byte) bool {
	if len(report) == 0 {
		c.LoggerError(logger, "sync-enclave: the seed sent no remote report -- refusing to take a trusted set from an unattested peer")
		return false
	}
	if !s.verifyRemoteReportInternal(report, string(certifiedCiphertext), true) {
		c.LoggerError(logger, "sync-enclave: the seed is NOT running our enclave build ("+uniqueID+"), or its report does not cover what it sent")
		c.LoggerError(logger, "    a joiner can only bootstrap trust from a seed running its own measurement.")
		c.LoggerError(logger, "    rebuild this node at the seed's version, or choose a seed running "+uniqueID+".")
		return false
	}
	c.LoggerInfo(logger, "sync-enclave: the seed attested as our own build "+uniqueID)
	return true
}

// bootstrapped reports whether this enclave holds any trust beyond itself.
//
// Two callers, both guarding against an enclave acting on an empty set:
//   - QueryEnclaveMeasurement, so a joiner can be told up front that this seed cannot bootstrap it;
//   - validateEnclaveIdentities, which must NOT run unbootstrapped.  Its verdict comes from counting
//     peers it trusts, so an empty set counts zero, concludes `inactive` for a perfectly good
//     identity, and broadcasts that verdict to the whole network.  Latent before this change too --
//     just unreachable, because everyone got their trust from genesis.
func (s *qadenaServer) bootstrapped() bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return len(s.sharedEnclaveParams.ActiveEnclaveIdentities) > 0
}
