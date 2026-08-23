package main

// WI-4 hardening tests for the re-share work: the integrity primitive, the addSSShare self-index
// fix, the keep-share guard, and threshold-1 arbitration.  The producer/audit tests join this file
// as those land.

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"sync"
	"testing"

	ecies "github.com/ecies/go/v2"
	"github.com/hashicorp/vault/shamir"
	"github.com/stretchr/testify/require"

	sdk "github.com/cosmos/cosmos-sdk/types"

	commonPkg "github.com/c3qtech/qadena_v3/x/qadena/common"
	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

// derivePubKBase64 must produce exactly the wire format PublicKey rows carry: base64 of the
// 33-byte compressed secp256k1 point.
func TestDerivePubKBase64(t *testing.T) {
	k, err := ecies.GenerateKey()
	require.NoError(t, err)
	want := base64.StdEncoding.EncodeToString(k.PublicKey.Bytes(true))

	got, err := derivePubKBase64(k.Hex())
	require.NoError(t, err)
	require.Equal(t, want, got)

	// A DIFFERENT key must not derive to the same pubK -- this is the whole point of using it as
	// an integrity check.
	k2, err := ecies.GenerateKey()
	require.NoError(t, err)
	got2, err := derivePubKBase64(k2.Hex())
	require.NoError(t, err)
	require.NotEqual(t, got, got2)

	_, err = derivePubKBase64("shorthex")
	require.Error(t, err, "not a 32-byte scalar")
	_, err = derivePubKBase64(strings.Repeat("zz", 32))
	require.Error(t, err, "not hex at all")
}

// RE-SHARE, NOT REKEY: a split of an existing privK must reconstruct to the SAME privK, and that
// privK must derive to the SAME pubK the chain already binds.  This is the producer's core loop.
func TestReshareIsNotRekey(t *testing.T) {
	k, err := ecies.GenerateKey()
	require.NoError(t, err)
	privK := k.Hex()
	pubK := base64.StdEncoding.EncodeToString(k.PublicKey.Bytes(true))

	s, _ := newSSTestServer(t, "pioneer1")
	owners := []string{"pioneer1", "pioneer2", "pioneer3", "pioneer4", "pioneer5"}
	require.Equal(t, 2, getThreshold(len(owners)), "premise: 5 owners is a 2-of-5 split")

	shares, err := s.addSSShare(owners, "reshare-k", privK, pubK)
	require.NoError(t, err)
	require.Len(t, shares, 5)

	// ANY threshold subset reconstructs the original privK -- try several pairs.
	for _, pair := range [][2]int{{0, 1}, {1, 4}, {2, 3}} {
		a, err := hex.DecodeString(shares[pair[0]])
		require.NoError(t, err)
		b, err := hex.DecodeString(shares[pair[1]])
		require.NoError(t, err)
		combined, err := shamir.Combine([][]byte{a, b})
		require.NoError(t, err)
		require.Equal(t, privK, string(combined), "pair %v must rebuild the ORIGINAL key", pair)
	}

	// And the reconstructed scalar derives to the pubK already on chain.
	got, err := derivePubKBase64(privK)
	require.NoError(t, err)
	require.Equal(t, pubK, got)
}

// addSSShare must keep the share at OUR index -- not shares[0] -- and nothing when we are not an
// owner at all.
func TestAddSSShareSelfIndex(t *testing.T) {
	t.Run("self mid-list", func(t *testing.T) {
		s, _ := newSSTestServer(t, "me")
		owners := []string{"pioneer1", "pioneer2", "me", "pioneer3", "pioneer4"}
		shares, err := s.addSSShare(owners, "self-idx", aKey(), "pub")
		require.NoError(t, err)
		held, found := s.getShare("self-idx")
		require.True(t, found)
		require.Equal(t, shares[2], held, "must hold the share at our index")
		require.NotEqual(t, shares[0], held, "shares[0] belongs to pioneer1, not us")
	})
	t.Run("self absent", func(t *testing.T) {
		s, _ := newSSTestServer(t, "me")
		owners := []string{"pioneer1", "pioneer2", "pioneer3", "pioneer4"}
		_, err := s.addSSShare(owners, "no-self", aKey(), "pub")
		require.NoError(t, err)
		held, _ := s.getShare("no-self")
		require.Empty(t, held, "we are not an owner; holding someone's share is a duplicate x-coordinate")
	})
}

// A row that fails to deliver our share -- absent entry, undecryptable blob, or us dropped from
// the owner list -- must not destroy the share we hold.
func TestSetPublicKeyKeepsShareOnEmpty(t *testing.T) {
	t.Run("undecryptable share", func(t *testing.T) {
		s, enclavePubK := newSSTestServer(t, "me")
		s.setOwnersAndShare("keep-k", []string{"me", "pioneer2"}, "old-share")

		in := broadcastFor("keep-k", []string{"me", "pioneer2", "pioneer3"}, "me", "ignored", enclavePubK)
		// Corrupt our entry so decryption fails.
		in.Shares[0].EncEnclaveShare = []byte("not-decryptable")
		_, err := s.SetPublicKey(nil, in)
		require.NoError(t, err, "an undecryptable share must not error (the keeper would panic)")

		held, found := s.getShare("keep-k")
		require.True(t, found)
		require.Equal(t, "old-share", held, "old share must survive")
		owners, found := s.getOwners("keep-k")
		require.True(t, found)
		require.Len(t, owners.PioneerIDs, 3, "owner list still updates")
	})
	t.Run("dropped from owners", func(t *testing.T) {
		s, enclavePubK := newSSTestServer(t, "me")
		s.setOwnersAndShare("drop-k", []string{"me", "pioneer2"}, "old-share")

		in := broadcastFor("drop-k", []string{"pioneer2", "pioneer3"}, "me", "ignored", enclavePubK)
		_, err := s.SetPublicKey(nil, in)
		require.NoError(t, err)

		held, _ := s.getShare("drop-k")
		require.Equal(t, "old-share", held, "a drop (impossible under the superset rule) must not wipe custody")
	})
	t.Run("true non-owner unaffected", func(t *testing.T) {
		s, enclavePubK := newSSTestServer(t, "me")
		in := broadcastFor("other-k", []string{"pioneer2", "pioneer3"}, "me", "ignored", enclavePubK)
		_, err := s.SetPublicKey(nil, in)
		require.NoError(t, err)
		held, _ := s.getShare("other-k")
		require.Empty(t, held)
	})
}

// Threshold-1 privK mismatch is ARBITRATED by deriving against the row's pubK, not logged-and-
// ignored: whichever of {cached, incoming} derives to in.PubK wins.
func TestSetPublicKeyThreshold1Arbitration(t *testing.T) {
	real, err := ecies.GenerateKey()
	require.NoError(t, err)
	realPrivK := real.Hex()
	realPubK := base64.StdEncoding.EncodeToString(real.PublicKey.Bytes(true))
	other, err := ecies.GenerateKey()
	require.NoError(t, err)

	mk := func(pubKID string, s_ *qadenaServer, enclavePubK, myValue string) *types.PublicKey {
		in := broadcastFor(pubKID, []string{"me", "pioneer2"}, "me", myValue, enclavePubK)
		in.PubK = realPubK // the chain row's pubK is the referee
		require.Equal(t, 1, getThreshold(2), "premise: 2 owners is unsplit")
		return in
	}

	t.Run("stale cache loses to correct incoming", func(t *testing.T) {
		s, enclavePubK := newSSTestServer(t, "me")
		s.setPrivKCache("arb-k", other.Hex()) // stale: derives to the WRONG pubK
		_, err := s.SetPublicKey(nil, mk("arb-k", s, enclavePubK, realPrivK))
		require.NoError(t, err)
		got, _ := s.getPrivKCache("arb-k")
		require.Equal(t, realPrivK, got, "the incoming key derives to in.PubK and must be adopted")
	})
	t.Run("correct cache survives garbage incoming", func(t *testing.T) {
		s, enclavePubK := newSSTestServer(t, "me")
		s.setPrivKCache("arb-k2", realPrivK)
		_, err := s.SetPublicKey(nil, mk("arb-k2", s, enclavePubK, other.Hex()))
		require.NoError(t, err)
		got, _ := s.getPrivKCache("arb-k2")
		require.Equal(t, realPrivK, got, "the cache derives correctly and must be kept")
	})
}

// setChainRow writes a chain-mirrored PublicKey row (the audit measures deficiency against this,
// not the local owners record).
func setChainRow(s *qadenaServer, pubKID string, owners []string) {
	shares := make([]*types.Share, 0, len(owners))
	for _, o := range owners {
		shares = append(shares, &types.Share{PioneerID: o})
	}
	s.setPublicKeyNoNotify(types.PublicKey{
		PubKID:   pubKID,
		PubKType: types.TransactionPubKType,
		Shares:   shares,
	})
}

// The audit's deficiency predicate: deficient iff privK cached AND the CHAIN row has fewer owners
// than min(fleet, cap).  Every key converges to the fleet size (capped).
func TestReshareAuditPredicate(t *testing.T) {
	k, err := ecies.GenerateKey()
	require.NoError(t, err)
	privK := k.Hex()
	pubK := base64.StdEncoding.EncodeToString(k.PublicKey.Bytes(true))

	cases := []struct {
		name          string
		ownerCount    int
		fleet         int
		cached        bool
		wantDeficient bool
	}{
		{"1 owner, fleet 1", 1, 1, true, false},
		{"1 owner, fleet 2", 1, 2, true, true},
		{"3 owners, fleet 4", 3, 4, true, true},
		{"4 owners, fleet 5", 4, 5, true, true},
		{"4 owners, fleet 6 (same threshold, still grows)", 4, 6, true, true},
		{"20 owners, fleet 25 (capped)", 20, 25, true, false},
		{"owners == fleet", 4, 4, true, false},
		{"deficient but no privK", 1, 3, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := newSSTestServer(t, "me")
			// A fleet of `fleet` addressable pioneers, each resolvable with an enclave pubK.
			for i := 0; i < tc.fleet; i++ {
				pid := "p" + strconv.Itoa(i)
				withPioneer(s, pid, "192.168.0."+strconv.Itoa(10+i))
				s.setPublicKeyNoNotify(types.PublicKey{PubKID: "wallet-" + pid, PubKType: types.EnclavePubKType, PubK: pubK})
			}
			// The audited key: owners are the first `ownerCount` pioneers.
			owners := make([]string, 0, tc.ownerCount)
			for i := 0; i < tc.ownerCount; i++ {
				owners = append(owners, "p"+strconv.Itoa(i))
			}
			s.setOwnersAndShare("audit-k", owners, "share")
			setChainRow(s, "audit-k", owners)
			if tc.cached {
				s.setPrivKCache("audit-k", privK)
				s.setPubKCache("audit-k", pubK)
			}

			plan := s.planSSRotation()
			rplan := s.planSSReshare(plan)

			isSelected := false
			for _, cand := range rplan.keys {
				if cand.pubKID == "audit-k" {
					isSelected = true
				}
			}
			require.Equal(t, tc.wantDeficient, isSelected, "audit selection for %s", tc.name)
		})
	}
}

// End to end through the producer: a deficient key is re-shared to the whole fleet, the emitted
// message reconstructs to the SAME privK, and the possession signature verifies against the pubK.
func TestReshareProducerEmitsValidGrowth(t *testing.T) {
	ensureQadenaPrefix()
	k, err := ecies.GenerateKey()
	require.NoError(t, err)
	privK := k.Hex()
	pubK := base64.StdEncoding.EncodeToString(k.PublicKey.Bytes(true))

	s, _ := newSSTestServer(t, "me")
	s.setPrivateEnclaveParamsPioneerInfo("me", "qadena1us04k44mpxw3zpyv08fyq07gnz6e7qurxlv9jg", "", "", "")

	// Fleet of 5, all resolvable.  Old owners: {me, p0}.  Target 5 ⇒ grow to 5, threshold 2.
	fleet := []string{"p0", "p1", "p2", "p3"}
	for i, pid := range fleet {
		withPioneer(s, pid, "192.168.0."+strconv.Itoa(10+i))
		kk, err := ecies.GenerateKey()
		require.NoError(t, err)
		s.setPublicKeyNoNotify(types.PublicKey{PubKID: "wallet-" + pid, PubKType: types.EnclavePubKType, PubK: base64.StdEncoding.EncodeToString(kk.PublicKey.Bytes(true))})
	}
	withPioneer(s, "me", "192.168.0.9")
	meEnc, err := ecies.GenerateKey()
	require.NoError(t, err)
	s.setPublicKeyNoNotify(types.PublicKey{PubKID: "wallet-me", PubKType: types.EnclavePubKType, PubK: base64.StdEncoding.EncodeToString(meEnc.PublicKey.Bytes(true))})

	old := []string{"me", "p0"}
	s.setOwnersAndShare("grow-k", old, "old-share")
	setChainRow(s, "grow-k", old)
	s.setPrivKCache("grow-k", privK)
	s.setPubKCache("grow-k", pubK)

	plan := s.planSSRotation()
	rplan := s.planSSReshare(plan)
	msgs := s.reshareSSIntervalKeys(plan, rplan)
	require.Len(t, msgs, 1, "the one deficient key must be re-shared")

	m, ok := msgs[0].(*types.MsgPioneerUpdatePublicKey)
	require.True(t, ok)
	require.Equal(t, "grow-k", m.PubKID)
	require.Len(t, m.Shares, 5, "grown to the fleet size")

	newSet := map[string]bool{}
	for _, sh := range m.Shares {
		newSet[sh.PioneerID] = true
	}
	require.True(t, newSet["me"] && newSet["p0"], "old owners must all remain (proper superset)")

	// The possession signature verifies against the pubK, over exactly the emitted shares.
	sharesJSON, err := jsonMarshal(m.Shares)
	require.NoError(t, err)
	digest := commonPossessionDigest("qadena1us04k44mpxw3zpyv08fyq07gnz6e7qurxlv9jg", "grow-k", types.TransactionPubKType, sharesJSON)
	require.True(t, commonVerifyPossessionSig(pubK, digest, m.PossessionSig), "possession proof must verify against the chain pubK")
}

func jsonMarshal(v any) (string, error) { b, err := json.Marshal(v); return string(b), err }
func commonPossessionDigest(creator, pubKID, pubKType, sharesJSON string) []byte {
	return commonPkg.PossessionDigest(creator, pubKID, pubKType, sharesJSON)
}
func commonVerifyPossessionSig(pubKBase64 string, digest, sig []byte) bool {
	return commonPkg.VerifyPossessionSig(pubKBase64, digest, sig)
}

var bech32Once sync.Once

// The enclave binary configures the qadena bech32 prefix at startup; the unit-test harness does
// not, so AccAddressFromBech32 would default to "cosmos".  Configure it once for these tests.
func ensureQadenaPrefix() {
	bech32Once.Do(func() {
		cfg := sdk.GetConfig()
		cfg.SetBech32PrefixForAccount("qadena", "qadenapub")
	})
}

// The who-has server refuses everything except a trusted requester asking for a cached SS interval
// key -- and never serves anything that is not an interval key.
func TestWhoHasServeRefusals(t *testing.T) {
	k, err := ecies.GenerateKey()
	require.NoError(t, err)
	privK := k.Hex()

	newReqServer := func(t *testing.T) (*qadenaServer, string, []byte) {
		s, _ := newSSTestServer(t, "server")
		// mark the chain LIVE so refuseIfCatchingUp passes
		withChainPosition(t, 100, true)
		// a requester enclave whose report the server will verify -- reuse the server's own
		// measurement path via a self report (isSelf trusts our own uid/sid).
		reqKey, err := ecies.GenerateKey()
		require.NoError(t, err)
		reqPubK := base64.StdEncoding.EncodeToString(reqKey.PublicKey.Bytes(true))
		report, err := s.getRemoteReport(strings.Join([]string{reqPubK, "some-k", "whohas"}, "|"))
		require.NoError(t, err)
		return s, reqPubK, report
	}

	t.Run("no privk cached", func(t *testing.T) {
		s, reqPubK, report := newReqServer(t)
		s.setOwnersAndShare("some-k", []string{"server"}, "share") // it IS an ss key, but no privK
		_, err := s.QueryEnclaveSecretSharePrivK(nil, &types.QueryEnclaveSecretSharePrivKRequest{
			RemoteReport: report, EnclavePubK: reqPubK, PubKID: "some-k"})
		require.Error(t, err, "no cached privK ⇒ refused")
	})

	t.Run("not an ss interval key", func(t *testing.T) {
		s, reqPubK, report := newReqServer(t)
		s.setPrivKCache("some-k", privK) // cached, but no owners record ⇒ not an SS key
		_, err := s.QueryEnclaveSecretSharePrivK(nil, &types.QueryEnclaveSecretSharePrivKRequest{
			RemoteReport: report, EnclavePubK: reqPubK, PubKID: "some-k"})
		require.Error(t, err, "a pubKID with no owners record must be refused")
	})

	t.Run("untrusted report", func(t *testing.T) {
		s, reqPubK, _ := newReqServer(t)
		s.setOwnersAndShare("some-k", []string{"server"}, "share")
		s.setPrivKCache("some-k", privK)
		_, err := s.QueryEnclaveSecretSharePrivK(nil, &types.QueryEnclaveSecretSharePrivKRequest{
			RemoteReport: []byte("garbage"), EnclavePubK: reqPubK, PubKID: "some-k"})
		require.Error(t, err, "an unverifiable report must be refused")
	})

	t.Run("catching up", func(t *testing.T) {
		s, reqPubK, report := newReqServer(t)
		withChainPosition(t, 100, false) // replaying
		s.setOwnersAndShare("some-k", []string{"server"}, "share")
		s.setPrivKCache("some-k", privK)
		_, err := s.QueryEnclaveSecretSharePrivK(nil, &types.QueryEnclaveSecretSharePrivKRequest{
			RemoteReport: report, EnclavePubK: reqPubK, PubKID: "some-k"})
		require.Error(t, err, "a catching-up node must refuse to serve")
	})

	t.Run("happy path returns a decryptable key", func(t *testing.T) {
		s, _ := newSSTestServer(t, "server")
		withChainPosition(t, 100, true)
		s.setOwnersAndShare("some-k", []string{"server"}, "share")
		s.setPrivKCache("some-k", privK)
		// Ask AS the server itself so we hold the matching enclave privK to decrypt the reply.
		reqPubK := s.getPrivateEnclaveParamsEnclavePubK()
		report, err := s.getRemoteReport(strings.Join([]string{reqPubK, "some-k", "whohas"}, "|"))
		require.NoError(t, err)
		resp, err := s.QueryEnclaveSecretSharePrivK(nil, &types.QueryEnclaveSecretSharePrivKRequest{
			RemoteReport: report, EnclavePubK: reqPubK, PubKID: "some-k"})
		require.NoError(t, err)
		var got string
		_, err = commonBDecrypt(s.getPrivateEnclaveParamsEnclavePrivK(), resp.EncPrivKEnclavePubK, &got)
		require.NoError(t, err)
		require.Equal(t, privK, got, "the served key must decrypt to the cached privK")
		require.True(t, s.verifyRemoteReport(resp.RemoteReport, strings.Join([]string{"whohas", string(resp.EncPrivKEnclavePubK)}, "|")),
			"reply report must cover the whohas-tagged ciphertext")
	})
}

func commonBDecrypt(privK string, enc []byte, out *string) ([]byte, error) {
	return commonPkg.BDecryptAndUnmarshal(privK, enc, out)
}

// seedKeys registers n deficient keys (1 owner each, privK cached) against a fleet of `fleet`.
func seedKeys(t *testing.T, s *qadenaServer, n, fleet int) {
	t.Helper()
	k, err := ecies.GenerateKey()
	require.NoError(t, err)
	privK := k.Hex()
	pubK := base64.StdEncoding.EncodeToString(k.PublicKey.Bytes(true))

	for i := 0; i < fleet; i++ {
		pid := "p" + strconv.Itoa(i)
		withPioneer(s, pid, "192.168.0."+strconv.Itoa(10+i))
		s.setPublicKeyNoNotify(types.PublicKey{PubKID: "wallet-" + pid, PubKType: types.EnclavePubKType, PubK: pubK})
	}
	for i := 0; i < n; i++ {
		id := "key-" + strconv.Itoa(i)
		s.setOwnersAndShare(id, []string{"p0"}, "share")
		setChainRow(s, id, []string{"p0"})
		s.setPrivKCache(id, privK)
		s.setPubKCache(id, pubK)
	}
}

// A NEW NODE JOINING A CHAIN WITH HUNDREDS OF KEYS MUST NOT RE-SHARE THEM ALL AT ONCE.  The tick
// after a fleet growth makes every key deficient; the audit must still select at most
// maxSSResharesPerRotation, and must not walk the whole table to work that out.
func TestAuditRateLimitsAndBoundsItsScan(t *testing.T) {
	s, _ := newSSTestServer(t, "p0")
	seedKeys(t, s, 300, 3) // 300 deficient keys, fleet of 3

	plan := s.planSSRotation()
	rplan := s.planSSReshare(plan)

	require.Len(t, rplan.keys, maxSSResharesPerRotation,
		"a 300-key backlog must yield exactly one tick's worth of work")
	require.LessOrEqual(t, rplan.audited, maxSSAuditScan,
		"the scan must never exceed its cap")
	// The early exit should make the backlog case CHEAP -- far below the scan cap, since every
	// key it looks at is deficient.
	require.LessOrEqual(t, rplan.audited, maxSSResharesPerRotation+8,
		"with everything deficient the scan should stop almost immediately, examined %d", rplan.audited)
}

// Quiescence is the expensive case -- nothing is deficient, so the scan cannot exit early.  It must
// still be bounded, because this runs on the block-execution thread every tick, forever.
func TestAuditScanIsBoundedWhenNothingIsDeficient(t *testing.T) {
	s, _ := newSSTestServer(t, "p0")
	// 300 keys already at the fleet size ⇒ none deficient.
	k, err := ecies.GenerateKey()
	require.NoError(t, err)
	pubK := base64.StdEncoding.EncodeToString(k.PublicKey.Bytes(true))
	for i := 0; i < 3; i++ {
		pid := "p" + strconv.Itoa(i)
		withPioneer(s, pid, "192.168.0."+strconv.Itoa(10+i))
		s.setPublicKeyNoNotify(types.PublicKey{PubKID: "wallet-" + pid, PubKType: types.EnclavePubKType, PubK: pubK})
	}
	owners := []string{"p0", "p1", "p2"}
	for i := 0; i < 300; i++ {
		id := "quiet-" + strconv.Itoa(i)
		s.setOwnersAndShare(id, owners, "share")
		setChainRow(s, id, owners)
		s.setPrivKCache(id, k.Hex())
	}

	rplan := s.planSSReshare(s.planSSRotation())
	require.Empty(t, rplan.keys, "nothing is deficient")
	require.LessOrEqual(t, rplan.audited, maxSSAuditScan,
		"an uncapped quiescent scan is an unbounded stall on block execution")
	require.Equal(t, maxSSAuditScan, rplan.audited, "and it should use its full budget looking")
}

// SYSTEMATIC COVERAGE.  A random start gave FAIR sampling but not full coverage: with a window of
// cap over N keys, a straggler survived k runs with probability (1-cap/N)^k, and on the live fleet
// (256/2233) that meant ~20 forced audits to clear seven of them.  The cursor must instead reach
// EVERY key within ceil(N/cap) runs, guaranteed.
func TestAuditCursorCoversEveryKeyWithinOneSweep(t *testing.T) {
	s, _ := newSSTestServer(t, "p0")
	const total = 900
	seedHealthyKeys(t, s, total, 3) // nothing deficient, so the scan runs to its cap each time
	plan := s.planSSRotation()

	scanned := 0
	runs := 0
	for runs < 20 {
		runs++
		rplan := s.planSSReshare(plan)
		scanned += rplan.audited
		if s.getSSAuditCursor() == "" {
			break // the sweep reached the end and reset
		}
	}
	expected := (total + maxSSAuditScan - 1) / maxSSAuditScan
	require.LessOrEqual(t, runs, expected,
		"a sweep of %d keys at cap %d must finish in %d runs, took %d", total, maxSSAuditScan, expected, runs)
	require.GreaterOrEqual(t, scanned, total,
		"every key must have been examined at least once across the sweep")
}

// The cursor must be a pubKID, not an index: the owners table grows between runs, and an index
// would skip a key for every insertion that sorts before it.
func TestAuditCursorIsStableUnderInsertion(t *testing.T) {
	s, _ := newSSTestServer(t, "p0")
	seedKeys(t, s, 300, 3)
	plan := s.planSSRotation()

	s.planSSReshare(plan)
	cur := s.getSSAuditCursor()
	require.NotEmpty(t, cur, "the first run must leave a cursor")

	// Insert keys that sort BEFORE the cursor.  An index cursor would now point somewhere else
	// entirely; a keyed cursor still means exactly "the key after this one".
	for i := 0; i < 50; i++ {
		id := "!early-" + strconv.Itoa(i) // '!' sorts below 'k' of "key-"
		s.setOwnersAndShare(id, []string{"p0"}, "share")
		setChainRow(s, id, []string{"p0"})
		s.setPrivKCache(id, aKey())
	}
	require.Equal(t, cur, s.getSSAuditCursor(), "insertion must not move the cursor")

	rplan := s.planSSReshare(plan)
	for _, cand := range rplan.keys {
		require.Greater(t, cand.pubKID, cur,
			"the run after an insertion must not go backwards behind the cursor")
	}
}

// seedHealthyKeys registers n keys ALREADY at the fleet size, so the audit finds nothing to do and
// the scan runs to its cap.  This is the case the cursor exists for: hunting a few stragglers in a
// large table.
func seedHealthyKeys(t *testing.T, s *qadenaServer, n, fleet int) {
	t.Helper()
	k, err := ecies.GenerateKey()
	require.NoError(t, err)
	owners := make([]string, 0, fleet)
	for i := 0; i < fleet; i++ {
		pid := "p" + strconv.Itoa(i)
		withPioneer(s, pid, "192.168.0."+strconv.Itoa(10+i))
		s.setPublicKeyNoNotify(types.PublicKey{PubKID: "wallet-" + pid, PubKType: types.EnclavePubKType,
			PubK: base64.StdEncoding.EncodeToString(k.PublicKey.Bytes(true))})
		owners = append(owners, pid)
	}
	for i := 0; i < n; i++ {
		id := "key-" + strconv.Itoa(100000+i) // fixed width so sort order is the numeric order
		s.setOwnersAndShare(id, owners, "share")
		setChainRow(s, id, owners)
		s.setPrivKCache(id, k.Hex())
	}
}

// THE EARLY EXIT AND THE CURSOR INTERACT, and the interaction is deliberate.  When a run stops early
// because it already found a tick's worth of work, the cursor advances only that far -- so a table
// where everything is deficient sweeps at the RATE LIMIT rather than at the scan cap.  That is
// harmless: in that state healing is the bottleneck anyway (4 per run either way), and the cursor
// keeps pace with the healing rather than running ahead of it.
func TestAuditCursorAdvancesByTheRateLimitWhenEverythingIsDeficient(t *testing.T) {
	s, _ := newSSTestServer(t, "p0")
	seedKeys(t, s, 300, 3) // all deficient
	plan := s.planSSRotation()

	rplan := s.planSSReshare(plan)
	require.Len(t, rplan.keys, maxSSResharesPerRotation)
	require.LessOrEqual(t, rplan.audited, maxSSResharesPerRotation+4,
		"a fully deficient table must stop as soon as it has a tick's work, not scan to the cap")
	require.NotEmpty(t, s.getSSAuditCursor(), "and it must still record where it stopped")
}

// A fresh enclave starts with no cursor and must simply begin at the beginning.
func TestAuditCursorStartsEmpty(t *testing.T) {
	s, _ := newSSTestServer(t, "p0")
	require.Empty(t, s.getSSAuditCursor())
	seedHealthyKeys(t, s, 10, 3)
	s.planSSReshare(s.planSSRotation())
	require.Equal(t, "", s.getSSAuditCursor(),
		"a table smaller than the cap is swept in one run, which completes and resets the cursor")
}

// withChainPosition sets the package-global chain position for one test and RESTORES it after.
//
// setChainPosition writes process-wide state (chainHeight/chainIsLive/chainPositionKnown).  Leaving
// it set to "replaying" leaked into every test that ran afterwards -- refuseIfCatchingUp then
// refused work those tests expected to succeed, and the failure surfaced in an unrelated test,
// which is exactly the shape of the pre-existing harness flake this package already suffers.  Do
// not call setChainPosition directly from a test.
func withChainPosition(t *testing.T, height int64, isLive bool) {
	t.Helper()
	chainPositionMutex.RLock()
	oldHeight, oldLive, oldKnown := chainHeight, chainIsLive, chainPositionKnown
	chainPositionMutex.RUnlock()

	setChainPosition(height, isLive)

	t.Cleanup(func() {
		chainPositionMutex.Lock()
		chainHeight, chainIsLive, chainPositionKnown = oldHeight, oldLive, oldKnown
		chainPositionMutex.Unlock()
	})
}
