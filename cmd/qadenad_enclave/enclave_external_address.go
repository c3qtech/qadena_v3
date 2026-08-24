package main

// Keeping a pioneer's PUBLISHED address true after the node moves.
//
// THE BUG THIS EXISTS FOR.  A pioneer's externalIPAddress reached the chain exactly once.
// updateIsValidator() was the only writer and it sits behind a latch -- `if in.IsProposer { if
// !PioneerIsValidator {...} }` -- that fires on the first proposed block and never re-arms.  The
// value it published came from sealed enclave params, written at init and restored from the seal
// on every start.  So after an IP change the chain advertised the old address forever: restart,
// re-bond, rotation and audit all left it alone.
//
// That is not cosmetic.  getAddressablePioneers() tests the field for EMPTINESS, not
// reachability, so a moved node keeps counting toward the re-share audit's owner target while
// being undialable -- the chain then overstates custody, and getSSPrivK and the who-has fallback
// both dial an address nobody is listening on.  A static lab fleet never notices; a cloud
// instance that gets a new public address on restart hits it the first time it reboots.
//
// THE INPUT WAS NEVER MISSING -- IT HAD NO PATH.  cmd/qadenad/cmd/enclave_selfstart.go reads
// config.toml's p2p.external_address on EVERY start and refuses to start without it.  But it only
// captured the value in the closure handed to ArmInitEnclaveDispatch, and that dispatch is gated
// on "the JarRegulator row for this jar id is absent".  On an established node that row exists,
// the gate is permanently shut, and the freshly-read address was discarded.  So the fix is not a
// new source of truth -- config.toml already is one, and the operator must edit it anyway for
// CometBFT to advertise a dialable address -- it is a delivery route for the value the node
// already holds.  It now rides on MsgUpdateHeight, which the keeper sends every 11 blocks.
//
// WHY TRUSTING THE HOST IS SAFE HERE, AND ONLY HERE.  enclave_params.go is emphatic about not
// trusting host-supplied values, and it is right.  An address is the one exception: the host
// already controls its own reachability, so a host that lies about its OWN address only makes
// itself unreachable.  That argument holds only because the chain-side handler
// (x/qadena/keeper/msg_server_pioneer_update_interval_public_key_i_d.go) now refuses to let any
// node rewrite ANOTHER node's row.  Without that refusal this would be an eclipse primitive.

import (
	"strconv"
	"strings"
	"sync"

	sdk "github.com/cosmos/cosmos-sdk/types"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"
	qadenatx "github.com/c3qtech/qadena_v3/x/qadena/client/tx"
	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

const extAddrTag = "ext-addr: "

// The republish loop guard.  A republish that never lands would otherwise be re-attempted at every
// opportunity forever -- so remember what was broadcast, and if the row STILL disagrees the next
// time we look, say so once and stop until the sealed value changes again.  A write that does not
// stick is a bug to surface, not a rate to limit; the chain-side refusal is the likeliest cause and
// it names itself in the node's own log.
var (
	extAddrMu        sync.Mutex
	extAddrBroadcast string // the address we last broadcast a republish for
	extAddrGaveUp    bool   // it did not stick; stop retrying until the sealed value moves
)

// noteExternalAddress folds the host-supplied address into the sealed params.
//
// EMPTY MEANS "NO OPINION", NEVER "BLANK THE SEAL".  A keeper older than this field leaves it
// unset, and every command other than `start` leaves it unset too; a new enclave paired with an
// old keeper during a rolling upgrade must keep the address it already has.
//
// Returns true when the sealed value actually changed, which is the caller's cue that a republish
// is owed.
func (s *qadenaServer) noteExternalAddress(addr string) bool {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return false
	}

	// NOTHING TO CORRECT BEFORE THERE IS AN IDENTITY TO CORRECT IT FOR.  On an uninitialized
	// enclave the address is InitEnclave's to set -- it carries one, and it is the only path that
	// can publish the row in the first place.  Taking it here would also CREATE
	// enclave_params_<uniqueID>.json on a node that has no params yet, purely to record an address
	// nothing reads.  (Harmless today, because the init short-circuit tests paramsPersisted AND a
	// non-empty PioneerID -- but that is a second condition holding this up, not a reason to lean
	// on it.)
	if s.getPrivateEnclaveParamsPioneerID() == "" {
		return false
	}

	if addr == s.getPrivateEnclaveParamsPioneerExternalIPAddress() {
		return false
	}

	old := s.getPrivateEnclaveParamsPioneerExternalIPAddress()
	s.setPrivateEnclaveParamsPioneerExternalIPAddress(addr)

	// saveEnclaveParamsIfChanged, NOT saveEnclaveParams.  This file holds
	// SealedTableSharedSecret -- the key to every stable-sealed row in both stores, with no backup
	// -- so every rewrite is a window in which a crash leaves it torn and those rows permanently
	// unreadable.  We only get here when the content genuinely differs, but routing through the
	// guarded writer keeps that property true if this is ever called on a hotter path.
	if !s.saveEnclaveParamsIfChanged() {
		c.LoggerError(logger, extAddrTag+"could not seal the new address "+addr)
		return false
	}

	c.LoggerInfo(logger, extAddrTag+"advertised address changed from "+orNone(old)+" to "+addr+
		" -- will republish this pioneer's row")

	// A fresh address re-arms the guard: whatever went wrong last time is no longer what we are
	// trying to publish.
	extAddrMu.Lock()
	extAddrBroadcast = ""
	extAddrGaveUp = false
	extAddrMu.Unlock()

	return true
}

// planExternalAddressRepublish decides, ON THE EXECUTION THREAD, whether this node's published
// address is wrong -- and returns the address to publish, or "" for nothing to do.
//
// This is the self-heal half: it compares the sealed address against the chain row rather than
// tracking whether a publish was ever attempted, so it also repairs a broadcast that was admitted
// and then dropped, and it converges on its own without a second operator action.
//
// It is self-limiting by construction: once the row matches the seal there is nothing to publish,
// so the steady state is a single comparison per call and no message at all.
func (s *qadenaServer) planExternalAddressRepublish() string {
	sealed := s.getPrivateEnclaveParamsPioneerExternalIPAddress()
	if sealed == "" {
		return ""
	}
	pioneerID := s.getPrivateEnclaveParamsPioneerID()
	if pioneerID == "" {
		// Not initialized yet; InitEnclave will publish the row with the address it was given.
		return ""
	}

	// getPioneerIPAddress READS s.CacheCtx, so this whole function is execution-thread only --
	// iterating that store from a goroutine racing block execution is the exact bug ssRotationPlan
	// was introduced to fix.  The caller detaches only the broadcast.
	rowIP, found := s.getPioneerIPAddress(pioneerID)
	if !found {
		// No row yet.  Publishing one is InitEnclave's and updateIsValidator's job, not ours --
		// this path only CORRECTS a row that already exists.
		return ""
	}
	if rowIP == sealed {
		return ""
	}

	extAddrMu.Lock()
	defer extAddrMu.Unlock()

	// THE PUBLISH LOOP GUARD.  We broadcast this exact address before and the row still disagrees,
	// so re-sending it will not help.  Say why once, loudly, and stop.
	if extAddrGaveUp {
		return ""
	}
	if extAddrBroadcast == sealed {
		extAddrGaveUp = true
		c.LoggerError(logger, extAddrTag+"republished "+sealed+" for "+pioneerID+
			" but the chain row still says "+orNone(rowIP)+" -- the transaction is not landing "+
			"(check for a rejection in this node's log) and will not be retried until the "+
			"advertised address changes again")
		return ""
	}

	extAddrBroadcast = sealed
	c.LoggerInfo(logger, extAddrTag+"chain row for "+pioneerID+" says "+orNone(rowIP)+
		" but this node is at "+sealed+" -- republishing")
	return sealed
}

// publishPioneerIntervalPublicKeyID builds and broadcasts this pioneer's interval-public-key row.
//
// Factored out of updateIsValidator so the first publish and every later correction build the row
// and its attestation in exactly ONE place -- the attested string and the message fields must stay
// in lockstep or the chain-side ClientVerifyRemoteReport rejects it, and two copies of that
// pairing is how they drift.
//
// BROADCASTS, SO IT MUST RUN DETACHED.  GenerateOrBroadcastTxCLISync goes out to this node's own
// mempool; doing that on the block execution thread would block consensus on a network round trip.
func (s *qadenaServer) publishPioneerIntervalPublicKeyID(externalIPAddress string) bool {
	pioneerID := s.getPrivateEnclaveParamsPioneerID()

	pwalletID, pwalletAddr, _, _, err := c.GetAddressByNameNoArmor(clientCtx, pioneerID)
	if err != nil {
		c.LoggerError(logger, extAddrTag+"couldn't resolve the pioneer key "+pioneerID+": "+err.Error())
		return false
	}

	// The attested string and the message must list the same five fields in the same order; the
	// chain rebuilds this join and verifies the quote against it.
	report, err := s.getRemoteReport(strings.Join([]string{
		pwalletAddr.String(),
		pwalletID,
		pioneerID,
		types.PioneerNodeType,
		externalIPAddress,
	}, "|"))
	if err != nil {
		c.LoggerError(logger, extAddrTag+"couldn't getRemoteReport "+err.Error())
		return false
	}

	msg := types.NewMsgPioneerUpdateIntervalPublicKeyID(
		pwalletAddr.String(),
		pwalletID,
		pioneerID,
		types.PioneerNodeType,
		externalIPAddress,
		report,
	)

	msgs := []sdk.Msg{msg}

	if s.RealEnclave {
		c.LoggerDebug(logger, extAddrTag+"msgs (redacted)")
	} else {
		c.LoggerDebug(logger, extAddrTag+"msgs "+c.PrettyPrint(msgs))
	}

	clientCtx = clientCtx.WithFrom(pwalletID).WithFromAddress(pwalletAddr).WithFromName(pioneerID)
	err, _ = qadenatx.GenerateOrBroadcastTxCLISync(clientCtx, RootCmd.Flags(),
		"external IP address of this pioneer", msgs...)
	if err != nil {
		c.LoggerError(logger, extAddrTag+"failed to broadcast "+err.Error())
		return false
	}
	return true
}

// orNone renders an address for a log line so an EMPTY one is visible as such rather than vanishing into
// the surrounding text.
func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

// ---------------------------------------------------------------------------------------------
// THE OTHER HALF: NOTICING THAT SOMEONE ELSE'S ADDRESS IS WRONG.
//
// Everything above assumes the operator edits config.toml when the node moves.  If they do not,
// the failure is invisible in the worst way: the node still dials OUT to its persistent_peers, so
// it stays in consensus, signs and proposes and looks healthy by every ordinary measure -- only
// INBOUND dials fail.  The start-time check in enclave_selfstart.go passes, because it tests for
// EMPTY, not for correct, and a stale address is perfectly well-formed.  Nothing above fires,
// because nothing changed as far as the node can see.
//
// So the trigger cannot be the safety net.  The net is making staleness DETECTABLE, and the
// information already exists: selectShareHolders sorts non-responders into a "silent" tier and
// then says nothing about WHO they were.  This names them, and escalates when the same peer is
// silent across consecutive rounds -- one silent round is a hiccup, three is an address that
// stopped working.
//
// WHY IT DOES NOT JUST REUSE selectShareHolders' PROBE.  That probe is skipped entirely when the
// fleet is at or below the share cap ("everyone owns regardless, so no probe could change the
// answer"), which is every fleet under 20 nodes -- including every fleet this has ever run on.
// Reporting must not have that blind spot, so it probes on its own.  Diagnostic only: it feeds no
// selection decision and CANNOT change the owner count, which is what keeps it clear of
// getThreshold.  The owner count is a security parameter -- at four owners the threshold crosses
// 1 -> 2 and a "share" stops being a whole key and becomes a Shamir fragment -- and deriving it
// from local network observation would let two nodes compute different thresholds from the same
// block.  That is the fork at height 30755.  Liveness may reorder holders; it must never count.
// ---------------------------------------------------------------------------------------------

// How many consecutive probe rounds a pioneer must miss before its silence is reported as an
// error rather than a note.  One round is a hiccup -- a restart, a busy moment, a dropped packet.
const silentRoundsBeforeAlarm = 3

var (
	silentRoundsMu sync.Mutex
	silentRounds   = map[string]int{} // pioneerID -> consecutive rounds silent
)

// reportUnreachablePioneers probes the fleet and says who did not answer.
//
// SAFE TO RUN DETACHED, and it must be: it does network I/O.  It touches no enclave state -- the
// pioneer set and their addresses arrive in the plan, snapshotted on the execution thread -- and
// it writes nothing any other node computes, so it cannot fork anything.
func (s *qadenaServer) reportUnreachablePioneers(plan *ssRotationPlan) {
	if len(plan.pioneers) == 0 {
		return
	}

	// Bounded by the same cap as the selection probe, for the same reason: a large fleet must not
	// turn a health report into a broadcast storm.
	candidates := plan.pioneers
	if len(candidates) > effectiveProbeCap() {
		var err error
		candidates, err = randomSubset(plan.pioneers, effectiveProbeCap())
		if err != nil {
			c.LoggerError(logger, extAddrTag+"could not sample peers to probe: "+err.Error())
			return
		}
	}

	live := s.probePioneerLiveness(candidates, plan.ips)
	answered := make(map[string]bool, len(live))
	for _, p := range live {
		answered[p] = true
	}

	silentRoundsMu.Lock()
	defer silentRoundsMu.Unlock()

	stale := 0
	for _, p := range candidates {
		if answered[p] {
			// Recovered, or never gone.  Drop it so a peer that comes back does not carry its old
			// count into a future outage and alarm on the first miss.
			delete(silentRounds, p)
			continue
		}
		silentRounds[p]++
		n := silentRounds[p]
		stale++
		addr := plan.ips[p]
		msg := extAddrTag + "pioneer " + p + " did not answer at " + orNone(addr) +
			" (" + strconv.Itoa(n) + " consecutive round(s))"

		// OUR OWN ADDRESS FAILING IS THE SHARPEST SIGNAL THERE IS, so it is worth separating from
		// a peer being down.  The probe set includes this node, and a node that cannot reach its
		// OWN published address has proved the address is wrong -- not that a peer is unhealthy.
		// This is the case the config.toml trigger cannot catch by itself: if the operator never
		// edits it, nothing changed as far as this node can see, so nothing republishes.  Said
		// immediately rather than after silentRoundsBeforeAlarm, because unlike a peer outage
		// there is no benign transient reading of it.
		if p == s.getPrivateEnclaveParamsPioneerID() {
			c.LoggerError(logger, extAddrTag+"THIS NODE cannot reach its own published address "+
				orNone(addr)+" -- peers cannot dial it either, and it is still counted as a share "+
				"owner.  If this node moved, set p2p.external_address in config.toml and restart; "+
				"the row is republished automatically from there")
			continue
		}

		if n >= silentRoundsBeforeAlarm {
			// The actionable phrasing, because by now the likeliest cause is not a hiccup: either
			// the node is down, or it MOVED and nobody updated its p2p.external_address.  It still
			// counts toward the owner target either way -- getAddressablePioneers tests the field
			// for emptiness, not reachability -- so the chain is overstating custody.
			c.LoggerError(logger, msg+" -- it is still counted as a share owner.  Either the node "+
				"is down, or its address changed and config.toml's p2p.external_address was never "+
				"updated on it")
		} else {
			c.LoggerInfo(logger, msg)
		}
	}

	c.LoggerInfo(logger, extAddrTag+"reachability: probed="+strconv.Itoa(len(candidates))+
		" answered="+strconv.Itoa(len(live))+" silent="+strconv.Itoa(stale)+
		" within="+ssLivenessProbeTimeout.String())
}
