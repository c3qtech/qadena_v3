package keeper_test

// PioneerHasDeparted -- the ONE definition of "this pioneer may be dropped from the owner set of
// SS interval keys it already holds".
//
// Why this is tested branch by branch rather than happy-path only: BOTH failure directions are
// silent.  Too eager and a routine downtime jail costs a re-share of every key that pioneer owns,
// churning owner sets for a node that was back in minutes and never lost its shares.  Too
// reluctant and the fleet goes on reporting custody it does not have, which is the whole problem
// the departure work exists to fix.  Neither shows up as an error, so the boundary is asserted on
// both sides and each "no" is asserted for its own reason.

import (
	"testing"

	"github.com/stretchr/testify/require"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/c3qtech/qadena_v3/x/qadena/keeper"
	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

// testPioneerNodeID is the pioneer's NODE ID, and it is deliberately NOT testValPubKID().
//
// Share.PioneerID holds a node id ("qfi-pioneer6" on a real fleet); a pubKID is a bech32 address.
// Both identify the same pioneer and each indexes the IntervalPublicKeyID table -- the primary key
// is (nodeID, nodeType), the secondary is pubKID -- so a lookup with the wrong one silently finds
// nothing rather than erroring.  An earlier version of this fixture used testValPubKID() for both
// roles, which made the two indexes coincide and hid a real bug: PioneerHasDeparted was reading
// the pubKID index with a node id, so no owner ever read as departed and no shrink could be
// accepted on a live chain.  Keeping them distinct here is what makes these tests able to fail.
const testPioneerNodeID = "qfi-pioneer-test"

// setGrace writes the grace explicitly at every call site, for the reason setReleaseGate gives:
// the default is non-zero, so a test wanting the disabled case must say so, and one wanting it on
// must not lean on the default to get it.
func setGrace(t *testing.T, k keeper.Keeper, ctx sdk.Context, blocks uint64) {
	t.Helper()
	params := k.GetParams(ctx)
	params.SsDepartureGrace = blocks
	require.NoError(t, k.SetParams(ctx, params))
}

// park puts the pioneer in the state the hook leaves behind: row present, address cleared, and
// the departure height stamped on the ROW (which is what both the chain and the enclave read).
func park(k keeper.Keeper, ctx sdk.Context, atHeight int64) {
	k.SetIntervalPublicKeyID(ctx, types.IntervalPublicKeyID{
		PubKID:         testValPubKID(),
		NodeID:         testPioneerNodeID,
		NodeType:       types.PioneerNodeType,
		DepartedHeight: atHeight,
	})
	k.SetParkedExternalAddress(ctx, types.ParkedExternalAddress{
		PubKID:            testValPubKID(),
		ExternalIPAddress: "1.2.3.4:26656",
	})
}

// THE GRACE BOUNDARY, FROM BOTH SIDES.  One block short is the case that protects a live fleet
// from its own routine jailing; exactly at the boundary is the case that makes the feature work at
// all.  A test asserting only the second passes just as well with no grace implemented.
func TestPioneerHasDepartedOnlyOnceTheGraceHasFullyElapsed(t *testing.T) {
	k, ctx, _ := setupHooks(t)
	setGrace(t, k, ctx, 100)
	park(k, ctx, 1_000)

	oneShort := ctx.WithBlockHeight(1_099)
	require.False(t, k.PioneerHasDeparted(oneShort, testPioneerNodeID),
		"99 blocks after parking is still away, not departed -- a jail that clears must cost nothing")

	exactly := ctx.WithBlockHeight(1_100)
	require.True(t, k.PioneerHasDeparted(exactly, testPioneerNodeID),
		"the grace is elapsed AT the boundary, not one block later")

	later := ctx.WithBlockHeight(5_000)
	require.True(t, k.PioneerHasDeparted(later, testPioneerNodeID))
}

// ZERO IS OFF, NOT "NO GRACE".  Params written before field 30 unmarshal zero, and so does an
// empty param store.  Reading that as "drop immediately" would rewrite owner sets the moment this
// binary ships, at a height replay cannot account for -- the same hazard ReleaseAddressOnUnbond
// documents for field 28.
func TestPioneerHasDepartedIsDisabledWhenTheGraceIsZero(t *testing.T) {
	k, ctx, _ := setupHooks(t)
	setGrace(t, k, ctx, 0)
	park(k, ctx, 1)

	require.False(t, k.PioneerHasDeparted(ctx.WithBlockHeight(1_000_000), testPioneerNodeID),
		"grace 0 means the feature is off; a million blocks must still not make a pioneer departed")
}

// A pioneer that was never parked is simply bonded.  The ordinary case, and the one every block
// takes.
func TestPioneerHasDepartedIsFalseForAPioneerThatWasNeverParked(t *testing.T) {
	k, ctx, _ := setupHooks(t)
	setGrace(t, k, ctx, 100)

	require.False(t, k.PioneerHasDeparted(ctx.WithBlockHeight(1_000_000), testPioneerNodeID))
}

// AN ENTRY PREDATING THE FIELD MUST NOT READ AS "PARKED AT GENESIS".  Treating height 0 as
// infinitely old would make every already-parked pioneer departed on the upgrade block -- the
// silent mass re-share this grace exists to prevent.
func TestPioneerHasDepartedTreatsAMissingHeightAsNotYetDeparted(t *testing.T) {
	k, ctx, _ := setupHooks(t)
	setGrace(t, k, ctx, 100)
	park(k, ctx, 0) // what a pre-field-30 entry unmarshals as

	require.False(t, k.PioneerHasDeparted(ctx.WithBlockHeight(1_000_000), testPioneerNodeID),
		"a parked entry with no recorded height is unknown-age, not ancient")
}

// THE HOOK RECORDS THE HEIGHT, and the clock resets on re-bond rather than being edited in place.
// This is what makes a flapping validator harmless: each genuine departure starts its own grace.
func TestParkRecordsTheHeightAndReBondResetsTheClock(t *testing.T) {
	k, ctx, h := setupHooks(t)
	enableRelease(t, k, ctx)
	setGrace(t, k, ctx, 100)
	seedPioneerRow(k, ctx, "1.2.3.4:26656")

	at500 := ctx.WithBlockHeight(500)
	require.NoError(t, h.AfterValidatorBeginUnbonding(at500, nil, testValAddr))

	row, found := k.GetIntervalPublicKeyIDByPubKID(at500, testValPubKID())
	require.True(t, found)
	require.Equal(t, int64(500), row.DepartedHeight, "the hook must stamp the height it parked at")

	// Still inside the grace, the pioneer re-bonds: the entry goes, so the clock cannot carry over
	// into a later unbond.
	at560 := ctx.WithBlockHeight(560)
	require.False(t, k.PioneerHasDeparted(at560, testPioneerNodeID))
	require.NoError(t, h.AfterValidatorBonded(at560, nil, testValAddr))
	_, found = k.GetParkedExternalAddress(at560, testValPubKID())
	require.False(t, found, "a restore consumes the parked entry")
	row, found = k.GetIntervalPublicKeyIDByPubKID(at560, testValPubKID())
	require.True(t, found)
	require.Zero(t, row.DepartedHeight, "and clears the departure height, which is what resets the clock")

	// It leaves again much later.  The grace is measured from THIS departure, so a height that
	// would have been past the deadline of the first one is not past this one's.
	at2000 := ctx.WithBlockHeight(2_000)
	require.NoError(t, h.AfterValidatorBeginUnbonding(at2000, nil, testValAddr))
	row, found = k.GetIntervalPublicKeyIDByPubKID(at2000, testValPubKID())
	require.True(t, found)
	require.Equal(t, int64(2_000), row.DepartedHeight)
	require.False(t, k.PioneerHasDeparted(ctx.WithBlockHeight(2_050), testPioneerNodeID),
		"the second departure gets a full grace of its own, not the remainder of the first")
	require.True(t, k.PioneerHasDeparted(ctx.WithBlockHeight(2_100), testPioneerNodeID))
}

// A SECOND TRANSITION WHILE ALREADY PARKED MUST NOT PUSH THE DEADLINE BACK.  staking can emit
// bonded->unbonding more than once without an intervening bond; if each one re-stamped the height,
// a validator flapping faster than the grace would never become departed at all.
func TestRepeatedUnbondingDoesNotRestartTheGrace(t *testing.T) {
	k, ctx, h := setupHooks(t)
	enableRelease(t, k, ctx)
	setGrace(t, k, ctx, 100)
	seedPioneerRow(k, ctx, "1.2.3.4:26656")

	require.NoError(t, h.AfterValidatorBeginUnbonding(ctx.WithBlockHeight(500), nil, testValAddr))
	require.NoError(t, h.AfterValidatorBeginUnbonding(ctx.WithBlockHeight(590), nil, testValAddr))

	row, found := k.GetIntervalPublicKeyIDByPubKID(ctx, testValPubKID())
	require.True(t, found)
	require.Equal(t, int64(500), row.DepartedHeight, "the FIRST departure sets the clock")
	require.True(t, k.PioneerHasDeparted(ctx.WithBlockHeight(600), testPioneerNodeID),
		"600 is 100 past the first departure, so the grace has elapsed despite the second transition")
}

// THE REPLAY GATE.  This row is chain state and therefore in the app hash, so a node replaying an
// existing chain's history with this binary must write exactly the bytes the old binary wrote.
// Every chain predating SsDepartureGrace has it at 0, so with the grace unset the hook must leave
// the row byte-identical -- no stamp.  Without this the first historical unbond would diverge.
func TestParkDoesNotStampTheHeightWhenTheGraceIsUnset(t *testing.T) {
	k, ctx, h := setupHooks(t)
	enableRelease(t, k, ctx)
	setGrace(t, k, ctx, 0) // a chain that has not opted in
	seedPioneerRow(k, ctx, "1.2.3.4:26656")

	at500 := ctx.WithBlockHeight(500)
	require.NoError(t, h.AfterValidatorBeginUnbonding(at500, nil, testValAddr))

	row, found := k.GetIntervalPublicKeyIDByPubKID(at500, testValPubKID())
	require.True(t, found)
	require.Zero(t, row.DepartedHeight,
		"with the grace unset the hook must write the pre-upgrade bytes: no departure height")
	require.Empty(t, row.ExternalIPAddress, "parking itself still happens -- only the stamp is gated")
}

// THE IDENTIFIER REGRESSION, pinned directly.
//
// PioneerHasDeparted takes a NODE ID.  Handed a pubKID -- the other identifier on the very same
// row -- it must say "no", because that is a lookup in the wrong index and not a departed pioneer.
// Asserting both directions on one parked row is what distinguishes "the function works" from
// "the function happens to agree because the fixture used one string for both".
func TestPioneerHasDepartedTakesANodeIDAndNotAPubKID(t *testing.T) {
	k, ctx, _ := setupHooks(t)
	setGrace(t, k, ctx, 100)
	park(k, ctx, 10)
	at := ctx.WithBlockHeight(500)

	require.True(t, k.PioneerHasDeparted(at, testPioneerNodeID),
		"the node id is the identifier Share.PioneerID carries, so it must resolve")
	require.False(t, k.PioneerHasDeparted(at, testValPubKID()),
		"a pubKID is not a node id -- resolving it would mean the pubKID index was consulted, "+
			"which is the bug that let every shrink be rejected on a live chain")
}
