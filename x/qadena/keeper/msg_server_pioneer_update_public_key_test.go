package keeper_test

// PioneerUpdatePublicKey's authorization, after the owner set was allowed to SHRINK.
//
// Every message below carries a genuinely valid attestation and a genuinely valid possession
// signature -- built, not mocked -- because that is the attacker's actual position: a node running
// a trusted measurement, holding the key it is re-sharing, saying something it has no right to
// say. A test whose messages fail attestation proves nothing about the rules that run afterwards.
//
// Two rules are under test and they replace one that used to do both jobs:
//
//	ELIGIBLE OWNERS  a stored owner may be dropped only once the chain says it DEPARTED.  The old
//	                 proper-superset rule could never drop anyone, which is why a departed pioneer
//	                 owned every key it ever held forever.
//	GENERATION CAS   the superset rule also rejected replays for free (a replay named the stored
//	                 set and failed strictness).  Once a shrink is legal it does not, and a stale
//	                 re-share would revert the owner list AND install shares from a split that no
//	                 longer matches the key -- garbage on recombination, not a lost update.

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	sdk "github.com/cosmos/cosmos-sdk/types"
	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/c3qtech/qadena_v3/x/qadena/common"
	"github.com/c3qtech/qadena_v3/x/qadena/keeper"
	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

const reshareKeyID = "qadena1reshare-test-key"

func hexOf(b []byte) string    { return hex.EncodeToString(b) }
func base64Of(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// setupReshareTest mirrors setupRowTest but hands back the keeper too, since these tests seed and
// then read the PublicKey row directly.
func setupReshareTest(t *testing.T) (keeper.Keeper, types.MsgServer, sdk.Context) {
	t.Helper()
	k, ms, goCtx := setupMsgServer(t)
	ctx := testCtx(goCtx)
	k.SetEnclaveIdentityNoEnclave(ctx, types.EnclaveIdentity{
		UniqueID: testUniqueID,
		SignerID: testSignerID,
		Status:   types.ActiveStatus,
	})
	return k, ms, ctx
}

// A real secp256k1 pair: the row stores the public half, and the test signs the possession proof
// with the private half exactly as a re-sharing enclave would.
func reshareKeyPair(t *testing.T) (privHex string, pubB64 string) {
	t.Helper()
	priv, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	return hexOf(priv.Serialize()), base64Of(priv.PubKey().SerializeCompressed())
}

func sharesFor(owners ...string) []*types.Share {
	out := make([]*types.Share, 0, len(owners))
	for _, o := range owners {
		out = append(out, &types.Share{PioneerID: o, EncEnclaveShare: []byte("share-for-" + o)})
	}
	return out
}

// reshareMsg builds a message whose attestation and possession signature both cover exactly what
// the handler re-derives, so the only thing a test can trip is the authorization in between.
func reshareMsg(t *testing.T, privHex string, expectedGen uint64, owners ...string) *types.MsgPioneerUpdatePublicKey {
	t.Helper()
	creator := testValPubKID()
	shares := sharesFor(owners...)

	b, err := json.Marshal(shares)
	require.NoError(t, err)
	sharesJSON := string(b)

	sig, err := common.SignPossession(privHex, common.PossessionDigest(creator, reshareKeyID, types.TransactionPubKType, sharesJSON))
	require.NoError(t, err)

	report := debugRemoteReport(t, strings.Join([]string{
		creator, reshareKeyID, types.TransactionPubKType, sharesJSON,
		hexOf(sig), strconv.FormatUint(expectedGen, 10),
	}, "|"))

	return &types.MsgPioneerUpdatePublicKey{
		Creator:            creator,
		PubKID:             reshareKeyID,
		PubKType:           types.TransactionPubKType,
		Shares:             shares,
		PossessionSig:      sig,
		RemoteReport:       report,
		ExpectedGeneration: expectedGen,
	}
}

// seedKey writes the row a mint would leave: owners, the public half, generation 0.
func seedKey(k keeper.Keeper, ctx sdk.Context, pubB64 string, owners ...string) {
	k.SetPublicKey(ctx, types.PublicKey{
		PubKID:     reshareKeyID,
		PubK:       pubB64,
		PubKType:   types.TransactionPubKType,
		Shares:     sharesFor(owners...),
		Generation: 0,
	})
}

// THE WHOLE POINT: a departed owner can finally be dropped.
func TestReshareMayDropADepartedOwner(t *testing.T) {
	k, ms, ctx := setupReshareTest(t)
	priv, pub := reshareKeyPair(t)
	seedKey(k, ctx, pub, "pioneer1", "pioneer2", testValPubKID())

	// testValPubKID's validator left and the grace has elapsed.
	setGrace(t, k, ctx, 100)
	park(k, ctx, 10)
	at := ctx.WithBlockHeight(500)
	require.True(t, k.PioneerHasDeparted(at, testValPubKID()))

	_, err := ms.PioneerUpdatePublicKey(at, reshareMsg(t, priv, 0, "pioneer1", "pioneer2"))
	require.NoError(t, err)

	row, found := k.GetPublicKey(at, reshareKeyID, types.TransactionPubKType)
	require.True(t, found)
	require.Len(t, row.Shares, 2, "the departed owner is gone from the row")
	require.Equal(t, uint64(1), row.Generation, "an accepted re-share advances the generation")
}

// AND THE GUARD THAT MAKES THAT SAFE: a live owner may not be dropped, however well attested the
// sender is.  Dropping one destroys a held share by omission.
func TestReshareMayNotDropAnEligibleOwner(t *testing.T) {
	k, ms, ctx := setupReshareTest(t)
	priv, pub := reshareKeyPair(t)
	seedKey(k, ctx, pub, "pioneer1", "pioneer2", testValPubKID())
	setGrace(t, k, ctx, 100) // nobody parked: every owner is eligible

	_, err := ms.PioneerUpdatePublicKey(ctx, reshareMsg(t, priv, 0, "pioneer1", "pioneer2"))
	require.ErrorIs(t, err, types.ErrOwnerStillEligible)
}

// Parked but INSIDE the grace is still eligible -- the case that keeps a routine downtime jail
// from costing a re-share.
func TestReshareMayNotDropAnOwnerStillInsideTheGrace(t *testing.T) {
	k, ms, ctx := setupReshareTest(t)
	priv, pub := reshareKeyPair(t)
	seedKey(k, ctx, pub, "pioneer1", "pioneer2", testValPubKID())

	setGrace(t, k, ctx, 100)
	park(k, ctx, 450)
	at := ctx.WithBlockHeight(500) // only 50 blocks in

	_, err := ms.PioneerUpdatePublicKey(at, reshareMsg(t, priv, 0, "pioneer1", "pioneer2"))
	require.ErrorIs(t, err, types.ErrOwnerStillEligible)
}

// GROWTH STILL WORKS.  Relaxing the superset rule must not have broken the case it existed for.
func TestReshareStillAcceptsPureGrowth(t *testing.T) {
	k, ms, ctx := setupReshareTest(t)
	priv, pub := reshareKeyPair(t)
	seedKey(k, ctx, pub, "pioneer1")

	_, err := ms.PioneerUpdatePublicKey(ctx, reshareMsg(t, priv, 0, "pioneer1", "pioneer2", "pioneer3"))
	require.NoError(t, err)

	row, _ := k.GetPublicKey(ctx, reshareKeyID, types.TransactionPubKType)
	require.Len(t, row.Shares, 3)
}

// THE REPLAY THE SUPERSET RULE USED TO CATCH FOR FREE.  The same message applied twice: the
// second time its expected generation no longer matches, so it is refused as stale rather than
// reverting the row to an older split.
func TestReshareIsRefusedWhenReplayed(t *testing.T) {
	k, ms, ctx := setupReshareTest(t)
	priv, pub := reshareKeyPair(t)
	seedKey(k, ctx, pub, "pioneer1")

	msg := reshareMsg(t, priv, 0, "pioneer1", "pioneer2")
	_, err := ms.PioneerUpdatePublicKey(ctx, msg)
	require.NoError(t, err)

	_, err = ms.PioneerUpdatePublicKey(ctx, msg)
	require.ErrorIs(t, err, types.ErrStaleGeneration, "a replayed re-share must not apply twice")
}

// A re-share computed against a generation the chain has moved past is refused even though it is
// attested, signed, and names a perfectly legal owner set.  This is the ordering case: two
// re-shares emitted close together must not apply out of order.
func TestReshareIsRefusedWhenComputedAgainstAnOlderGeneration(t *testing.T) {
	k, ms, ctx := setupReshareTest(t)
	priv, pub := reshareKeyPair(t)
	seedKey(k, ctx, pub, "pioneer1")

	_, err := ms.PioneerUpdatePublicKey(ctx, reshareMsg(t, priv, 0, "pioneer1", "pioneer2"))
	require.NoError(t, err)

	stale := reshareMsg(t, priv, 0, "pioneer1", "pioneer2", "pioneer3")
	_, err = ms.PioneerUpdatePublicKey(ctx, stale)
	require.ErrorIs(t, err, types.ErrStaleGeneration)

	fresh := reshareMsg(t, priv, 1, "pioneer1", "pioneer2", "pioneer3")
	_, err = ms.PioneerUpdatePublicKey(ctx, fresh)
	require.NoError(t, err, "the same change, recomputed against the current generation, is fine")
}

// The expected generation is inside the attested string, so editing it in flight invalidates the
// report.  Without that, the CAS value would be the one field an intermediary could rewrite.
func TestReshareGenerationIsCoveredByTheAttestation(t *testing.T) {
	k, ms, ctx := setupReshareTest(t)
	priv, pub := reshareKeyPair(t)
	seedKey(k, ctx, pub, "pioneer1")

	msg := reshareMsg(t, priv, 0, "pioneer1", "pioneer2")
	msg.ExpectedGeneration = 7 // the report still covers 0

	_, err := ms.PioneerUpdatePublicKey(ctx, msg)
	require.ErrorIs(t, err, types.ErrInvalidEnclave)
}

// Emptying the owner set is not a custody change this message may express: it would leave a key
// on chain that nobody is recorded as holding.
func TestReshareMayNotEmptyTheOwnerSet(t *testing.T) {
	k, ms, ctx := setupReshareTest(t)
	priv, pub := reshareKeyPair(t)
	seedKey(k, ctx, pub, testValPubKID())

	setGrace(t, k, ctx, 100)
	park(k, ctx, 10)
	at := ctx.WithBlockHeight(500)

	_, err := ms.PioneerUpdatePublicKey(at, reshareMsg(t, priv, 0))
	require.ErrorIs(t, err, types.ErrOwnerStillEligible)
}
