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
//   handover    an upgrade carries the whole sealed params, trusted set included, from the previous
//               measurement -- authenticated against the one the operator named in
//               --upgrade-from-enclave-unique-id.  See verifyUpgradeSourceIsExpected.
//
// Those last two are the same problem in different clothes, and BOTH were once served invisibly by
// the mirrored store: a new enclave read trust from chain rows and never noticed it was
// bootstrapping.  Each now names an anchor it can actually check -- our own measurement for a
// joiner, the operator's stated measurement for an upgrade.
//
// HOW TRUST IS LOST:
//
//   a mirror push with Status inactive -- governance or a quorum deactivation flowing in.  Note the
//   asymmetry: a mirror push may REMOVE trust but never add it.  That is what keeps a hostile node
//   unable to do anything except reduce what it is trusted with.
//
// REPLAY APPLIES BOTH DIRECTIONS, IN ORDER.  Historical transitions are not ignored: the stream is
// consensus-ordered and immutable, so processing it converges on the chain's final view.  Applying
// grants but not revocations would ratchet trust upwards; the age limit therefore guards LIVE
// messages only, where a peer chooses what to send.  Whatever fails to verify along the way -- old
// DCAP collateral will -- is caught by reconcileTrustOnGoingLive and settled by a quorum.
//
// MRSIGNER is deliberately absent from all of this.  It cannot anchor anything here: the signing
// key ships in the repo, so anyone can produce a leaky enclave whose attestation is genuine and
// whose MRSIGNER matches.  Only MRENCLAVE distinguishes builds.

import (
	"strconv"
	"sync"
	"time"

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

// How long to wait for one pioneer's answer when validating an identity.  Generous next to a
// healthy round trip and short next to the retry, which is 5 blocks away: the cost of giving up on
// a slow peer is one retry, while the cost of waiting forever is that no identity is ever validated
// again on this node.
const validatePeerTimeout = 10 * time.Second

// How far AHEAD of our watermark an attestation may be and still grant trust.  Not zero: the
// watermark is raised from UpdateHeight, and a message generated during the same block can arrive
// with a height a step ahead of what we have recorded.
const attestationFutureMarginBlocks = 2

// trustGainWithinWatermark decides whether an attestation is recent enough, RELATIVE TO THIS
// ENCLAVE'S OWN HEIGHT WATERMARK, to grant trust.
//
// The watermark replaces the old `isLive` test, which asked the host a question the host had every
// reason to lie about: setting isLive=false skipped the age check, so a genuine historical promotion
// of a since-retired build could be replayed over the socket to gain trust for it.  The watermark is
// the enclave's own sealed, monotonic memory of how far the chain has gone, so no answer from the
// host moves it.
//
// It separates the two cases the old test conflated:
//
//	replaying honestly   the watermark is LOW and climbs with the messages, so in-sequence
//	                     promotions have height close to it and still apply.
//	fed out of era       the watermark is already high, so a promotion from far behind is refused,
//	                     whatever the host claims about liveness.
//
// The height is bound inside the report's certifyData, so it cannot be restated to beat this.
//
// SCOPE THE CLAIM: this removes the isLive lever for INJECTION into a node's current state.  It does
// NOT address rollback -- the watermark lives inside the sealed params, so a host that restores an
// older authentic copy restores an older watermark with it.  See docs/ENCLAVE-THREAT-MODEL.md.
func trustGainWithinWatermark(reportHeight int64, hwm int64, what string) bool {
	if hwm == 0 {
		// No height history yet: this enclave has never seen a block, so it has nothing to judge
		// against.  Happens during init and sync-enclave, before the node starts -- and those paths
		// authenticate by MEASUREMENT rather than by age, which is the stronger check anyway.
		c.LoggerDebug(logger, "no height watermark yet; not judging the age of "+what)
		return true
	}
	age := hwm - reportHeight
	if age > attestationMaxAgeBlocks {
		c.LoggerInfo(logger, "refusing trust gain from "+what+" attested at height "+
			strconv.FormatInt(reportHeight, 10)+": "+strconv.FormatInt(age, 10)+
			" blocks behind our watermark "+strconv.FormatInt(hwm, 10)+
			", limit is "+strconv.FormatInt(attestationMaxAgeBlocks, 10))
		return false
	}
	if age < -attestationFutureMarginBlocks {
		// Ahead of us by more than the slack a node legitimately has while catching up within a
		// block or two.  Either a broken peer or an attempt to buy a quote unlimited lifetime.
		c.LoggerError(logger, "refusing trust gain from "+what+" attested at height "+
			strconv.FormatInt(reportHeight, 10)+", which is ahead of our watermark "+
			strconv.FormatInt(hwm, 10))
		return false
	}
	c.LoggerDebug(logger, "accepting "+what+" attested at height "+strconv.FormatInt(reportHeight, 10)+
		", "+strconv.FormatInt(age, 10)+" blocks behind the watermark")
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

// refuseIfCatchingUp guards the handlers that hand secrets to a peer.
//
// While a node replays, its trusted set is mid-reconstruction: historical transitions are being
// applied in order, some attestations may not verify until the reconcile settles them, and the set
// genuinely does not yet describe the present.  Answering a secret-releasing request from that state
// means answering on a view we know to be provisional -- in either direction, refusing a legitimate
// peer or serving one the chain has since retired.
//
// A node that is not caught up has no business being a source of secrets at all.  It is not the
// authority on anything yet, and the caller can simply ask a node that is.
func (s *qadenaServer) refuseIfCatchingUp(what string) error {
	_, isLive, known := currentChainPosition()
	if !known || isLive {
		return nil
	}
	height, _, _ := currentChainPosition()
	c.LoggerInfo(logger, "refusing "+what+" at height "+strconv.FormatInt(height, 10)+
		": this node is still catching up, so its trusted set does not yet describe the present -- ask a node that is caught up")
	return types.ErrGenericEnclave
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

// verifyUpgradeSourceIsExpected authenticates the OLD enclave during an upgrade handover.
//
// A freshly built measurement has no trusted set -- acquiring one is part of what it is here to do
// -- so it cannot ask "is this measurement trusted".  What it can ask is whether the report really
// comes from the measurement the OPERATOR named when starting it:
//
//	qadenad_enclave --upgrade-from-enclave-unique-id=<old>
//
// The measurement in a remote report is produced by the hardware and cannot be restated, so this
// compares an operator instruction against an unforgeable fact.  It is the same kind of anchor as
// verifySeedIsOurBuild, differing only in where the expected measurement comes from: there it is
// necessarily our own, here it is deliberately a different one.
func (s *qadenaServer) verifyUpgradeSourceIsExpected(report []byte, certifiedData string, expectedUniqueID string) bool {
	if expectedUniqueID == "" {
		c.LoggerError(logger, "upgrade handover with no --upgrade-from-enclave-unique-id: refusing to adopt state from an unnamed enclave")
		return false
	}
	if len(report) == 0 {
		c.LoggerError(logger, "upgrade handover: the old enclave sent no remote report")
		return false
	}
	ok, reportUniqueID, reportSignerID := s.remoteReportMeasurement(report, certifiedData)
	if !ok {
		c.LoggerError(logger, "upgrade handover: the old enclave's report does not verify, or does not cover the state it sent")
		return false
	}
	if reportUniqueID != expectedUniqueID {
		c.LoggerError(logger, "upgrade handover: expected state from "+expectedUniqueID+
			" but the report says "+reportUniqueID+" -- refusing")
		return false
	}
	c.LoggerInfo(logger, "upgrade handover: the old enclave attested as "+reportUniqueID+
		" (signer "+reportSignerID+"), which is the measurement this run was told to upgrade from")
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
