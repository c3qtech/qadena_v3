package keeper_test

// The park/restore staking hooks (keeper/staking_hooks.go), tested branch by branch.
//
// Two properties matter more than any single case and are asserted throughout:
//
//  1. NO BRANCH EVER RETURNS AN ERROR.  MultiStakingHooks propagates a non-nil return into
//     staking's EndBlock, which is a consensus halt -- so every case, including the anomalous
//     ones, requires nil and looks for an event instead.
//  2. THE PARKED VALUE IS NEVER LOST OR CLOBBERED.  The enclave will not republish an emptied
//     row (its first-publication latch is sealed and its self-heal refuses empty rows), so the
//     parked copy is the ONLY way a pioneer becomes addressable again.  Losing it -- to a second
//     jail cycle, a validator removal, or a restore against a missing row -- is a permanently
//     unaddressable pioneer.

import (
	"testing"

	"github.com/stretchr/testify/require"

	sdkmath "cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"

	keepertest "github.com/c3qtech/qadena_v3/testutil/keeper"
	"github.com/c3qtech/qadena_v3/x/qadena/keeper"
	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

// A fixed operator address, so every test derives the same row PubKID the hook will derive:
// sdk.AccAddress re-encodes the same bytes the validator operator address carries.
var testValAddr = sdk.ValAddress([]byte("park-restore-test-op"))

func testValPubKID() string { return sdk.AccAddress(testValAddr).String() }

// setupHooks returns the keeper, a context the setters accept (IsCheckTx skips the enclave
// forward -- there is none behind the test harness), and the hooks under test.
func setupHooks(t *testing.T) (keeper.Keeper, sdk.Context, keeper.Hooks) {
	t.Helper()
	k, ctx := keepertest.QadenaKeeper(t)
	return k, ctx.WithIsCheckTx(true), k.Hooks()
}

func enableRelease(t *testing.T, k keeper.Keeper, ctx sdk.Context) {
	t.Helper()
	params := k.GetParams(ctx)
	params.ReleaseAddressOnUnbond = true
	require.NoError(t, k.SetParams(ctx, params))
}

// seedPioneerRow writes the row the way a live chain holds one mid-life: address published,
// service fields set, and a PreviousPubKID from an earlier rotation.  Every field besides the
// address must survive a park untouched.
func seedPioneerRow(k keeper.Keeper, ctx sdk.Context, ip string) {
	k.SetIntervalPublicKeyID(ctx, types.IntervalPublicKeyID{
		PubKID:              testValPubKID(),
		NodeID:              "pioneer-hook-test",
		NodeType:            types.PioneerNodeType,
		ExternalIPAddress:   ip,
		ServiceProviderType: "test-srv-prv",
		HomePioneerID:       "pioneer-home",
		PreviousPubKID:      "rotated-away-key",
	})
}

func eventsOfType(ctx sdk.Context, typ string) []sdk.Event {
	var out []sdk.Event
	for _, ev := range ctx.EventManager().Events() {
		if ev.Type == typ {
			out = append(out, ev)
		}
	}
	return out
}

// The gate.  Default params carry the proto3 zero, so an un-upgraded chain and a replay of
// pre-upgrade history both take this branch: no write, no park, no event -- byte-identical state
// is what makes shipping the binary consensus-safe.
func TestHooksParamOffIsNoOp(t *testing.T) {
	k, ctx, h := setupHooks(t)
	seedPioneerRow(k, ctx, "10.0.0.1")

	ctx = ctx.WithEventManager(sdk.NewEventManager())
	require.NoError(t, h.AfterValidatorBeginUnbonding(ctx, nil, testValAddr))

	row, found := k.GetIntervalPublicKeyIDByPubKID(ctx, testValPubKID())
	require.True(t, found)
	require.Equal(t, "10.0.0.1", row.ExternalIPAddress, "gate off must leave the row untouched")
	_, parked := k.GetParkedExternalAddress(ctx, testValPubKID())
	require.False(t, parked)
	require.Empty(t, ctx.EventManager().Events(), "gate off must be silent -- events would differ across a replay")
}

// A validator with no pioneer row is normal on a mixed chain and an anomaly on this fleet; the
// hook cannot know which, so it says what it saw and touches nothing.
func TestHooksUnbondWithNoRowEmitsEventAndNil(t *testing.T) {
	k, ctx, h := setupHooks(t)
	enableRelease(t, k, ctx)

	ctx = ctx.WithEventManager(sdk.NewEventManager())
	require.NoError(t, h.AfterValidatorBeginUnbonding(ctx, nil, testValAddr))

	require.Len(t, eventsOfType(ctx, types.EventTypeUnbondPioneerRowNotFound), 1,
		"the only signal an operator gets that the mapping did not resolve")
}

// The park itself: address into the parked store, row emptied THROUGH the full-service setter --
// so every other field, including the rotation-grace pointer PreviousPubKID, must come through
// exactly as it was.
func TestHooksParkClearsAddressAndPreservesEveryOtherField(t *testing.T) {
	k, ctx, h := setupHooks(t)
	enableRelease(t, k, ctx)
	seedPioneerRow(k, ctx, "10.0.0.1")

	ctx = ctx.WithEventManager(sdk.NewEventManager())
	require.NoError(t, h.AfterValidatorBeginUnbonding(ctx, nil, testValAddr))

	row, found := k.GetIntervalPublicKeyIDByPubKID(ctx, testValPubKID())
	require.True(t, found)
	require.Empty(t, row.ExternalIPAddress, "the emptied row is what excludes the pioneer from NEW interval keys")
	require.Equal(t, "test-srv-prv", row.ServiceProviderType)
	require.Equal(t, "pioneer-home", row.HomePioneerID)
	require.Equal(t, "rotated-away-key", row.PreviousPubKID,
		"a same-PubKID rewrite must carry the existing pointer, not void the rotation grace")

	parked, found := k.GetParkedExternalAddress(ctx, testValPubKID())
	require.True(t, found)
	require.Equal(t, "10.0.0.1", parked.ExternalIPAddress)
	require.Len(t, eventsOfType(ctx, types.EventTypeExternalAddressParked), 1)
}

// Repeated transitions while already parked -- a jail cycle bouncing in and out of the unbonding
// state -- must not overwrite the parked address with the row's now-empty one.
func TestHooksDoubleUnbondDoesNotClobberTheParkedValue(t *testing.T) {
	k, ctx, h := setupHooks(t)
	enableRelease(t, k, ctx)
	seedPioneerRow(k, ctx, "10.0.0.1")

	require.NoError(t, h.AfterValidatorBeginUnbonding(ctx, nil, testValAddr))

	ctx = ctx.WithEventManager(sdk.NewEventManager())
	require.NoError(t, h.AfterValidatorBeginUnbonding(ctx, nil, testValAddr))

	parked, found := k.GetParkedExternalAddress(ctx, testValPubKID())
	require.True(t, found)
	require.Equal(t, "10.0.0.1", parked.ExternalIPAddress,
		"a second unbond while parked would otherwise park the empty row over the real address")
	require.Empty(t, eventsOfType(ctx, types.EventTypeExternalAddressParked),
		"an already-empty row has nothing to park, so nothing to announce")
}

// The round trip: re-bonding restores the address and consumes the parked entry.
func TestHooksRestorePutsTheAddressBackAndDeletesParked(t *testing.T) {
	k, ctx, h := setupHooks(t)
	enableRelease(t, k, ctx)
	seedPioneerRow(k, ctx, "10.0.0.1")
	require.NoError(t, h.AfterValidatorBeginUnbonding(ctx, nil, testValAddr))

	ctx = ctx.WithEventManager(sdk.NewEventManager())
	require.NoError(t, h.AfterValidatorBonded(ctx, nil, testValAddr))

	row, found := k.GetIntervalPublicKeyIDByPubKID(ctx, testValPubKID())
	require.True(t, found)
	require.Equal(t, "10.0.0.1", row.ExternalIPAddress)
	_, stillParked := k.GetParkedExternalAddress(ctx, testValPubKID())
	require.False(t, stillParked, "a consumed parked entry left behind would restore a stale address years later")
	require.Len(t, eventsOfType(ctx, types.EventTypeExternalAddressRestored), 1)
}

// A bond with nothing parked is every validator's FIRST bond -- and any bond from before the
// feature was enabled.  First publication belongs to the enclave (the sealed latch, on the first
// proposed block), so the hook's silence is correctness, not a missed case.
func TestHooksBondWithNothingParkedIsSilent(t *testing.T) {
	k, ctx, h := setupHooks(t)
	enableRelease(t, k, ctx)
	seedPioneerRow(k, ctx, "10.0.0.1")

	ctx = ctx.WithEventManager(sdk.NewEventManager())
	require.NoError(t, h.AfterValidatorBonded(ctx, nil, testValAddr))

	row, _ := k.GetIntervalPublicKeyIDByPubKID(ctx, testValPubKID())
	require.Equal(t, "10.0.0.1", row.ExternalIPAddress, "nothing parked, nothing to write")
	require.Empty(t, ctx.EventManager().Events())
}

// An operator who republished manually while unbonded (a pioneer can always update its OWN row)
// has newer information than the parked copy.  Restoring over it is the one way this feature
// could move a node backwards -- so the parked value is discarded instead, and says so.
func TestHooksRestoreOverManualRepublishDiscardsParked(t *testing.T) {
	k, ctx, h := setupHooks(t)
	enableRelease(t, k, ctx)
	seedPioneerRow(k, ctx, "10.0.0.1")
	require.NoError(t, h.AfterValidatorBeginUnbonding(ctx, nil, testValAddr))

	// The manual republish: same row, same PubKID, a new address.
	row, _ := k.GetIntervalPublicKeyIDByPubKID(ctx, testValPubKID())
	row.ExternalIPAddress = "10.0.0.99"
	k.SetIntervalPublicKeyID(ctx, row)

	ctx = ctx.WithEventManager(sdk.NewEventManager())
	require.NoError(t, h.AfterValidatorBonded(ctx, nil, testValAddr))

	row, _ = k.GetIntervalPublicKeyIDByPubKID(ctx, testValPubKID())
	require.Equal(t, "10.0.0.99", row.ExternalIPAddress, "the newer manual address must win")
	_, stillParked := k.GetParkedExternalAddress(ctx, testValPubKID())
	require.False(t, stillParked)
	require.Len(t, eventsOfType(ctx, types.EventTypeExternalAddressParkStale), 1)
	require.Empty(t, eventsOfType(ctx, types.EventTypeExternalAddressRestored))
}

// A parked value whose row has vanished (a deliberate row removal while unbonded) is kept, not
// dropped: the row may come back, and the parked copy is the only path to addressability.
func TestHooksRestoreWithMissingRowKeepsParked(t *testing.T) {
	k, ctx, h := setupHooks(t)
	enableRelease(t, k, ctx)
	seedPioneerRow(k, ctx, "10.0.0.1")
	require.NoError(t, h.AfterValidatorBeginUnbonding(ctx, nil, testValAddr))

	k.RemoveIntervalPublicKeyID(ctx, "pioneer-hook-test", types.PioneerNodeType)

	ctx = ctx.WithEventManager(sdk.NewEventManager())
	require.NoError(t, h.AfterValidatorBonded(ctx, nil, testValAddr))

	parked, found := k.GetParkedExternalAddress(ctx, testValPubKID())
	require.True(t, found, "dropping the parked value against a missing row would be irreversible")
	require.Equal(t, "10.0.0.1", parked.ExternalIPAddress)
	require.Len(t, eventsOfType(ctx, types.EventTypeUnbondPioneerRowNotFound), 1)
}

// A row under the validator's PubKID that is NOT a pioneer row is out of scope: the hook must
// treat it exactly like no row at all and leave it alone.
func TestHooksNonPioneerRowIsNotTouched(t *testing.T) {
	k, ctx, h := setupHooks(t)
	enableRelease(t, k, ctx)
	k.SetIntervalPublicKeyID(ctx, types.IntervalPublicKeyID{
		PubKID:            testValPubKID(),
		NodeID:            types.SSNodeID,
		NodeType:          types.SSNodeType,
		ExternalIPAddress: "10.0.0.1",
	})

	ctx = ctx.WithEventManager(sdk.NewEventManager())
	require.NoError(t, h.AfterValidatorBeginUnbonding(ctx, nil, testValAddr))

	row, found := k.GetIntervalPublicKeyIDByPubKID(ctx, testValPubKID())
	require.True(t, found)
	require.Equal(t, "10.0.0.1", row.ExternalIPAddress, "only Pioneer rows carry a peer-dialled address")
	_, parked := k.GetParkedExternalAddress(ctx, testValPubKID())
	require.False(t, parked)
	require.Len(t, eventsOfType(ctx, types.EventTypeUnbondPioneerRowNotFound), 1)
}

// Validator removal -- the unbonding period completing with nothing delegated -- must NOT consume
// the parked entry: the same pioneer key can create a fresh validator later, and its bond hook is
// the only thing that will ever make the pioneer addressable again.
func TestHooksAfterValidatorRemovedKeepsParked(t *testing.T) {
	k, ctx, h := setupHooks(t)
	enableRelease(t, k, ctx)
	seedPioneerRow(k, ctx, "10.0.0.1")
	require.NoError(t, h.AfterValidatorBeginUnbonding(ctx, nil, testValAddr))

	require.NoError(t, h.AfterValidatorRemoved(ctx, nil, testValAddr))

	parked, found := k.GetParkedExternalAddress(ctx, testValPubKID())
	require.True(t, found)
	require.Equal(t, "10.0.0.1", parked.ExternalIPAddress)

	// And the full cycle still closes: a recreated validator bonding restores it.
	require.NoError(t, h.AfterValidatorBonded(ctx, nil, testValAddr))
	row, _ := k.GetIntervalPublicKeyIDByPubKID(ctx, testValPubKID())
	require.Equal(t, "10.0.0.1", row.ExternalIPAddress)
}

// Every method, both gate positions, no row / row / parked -- nil everywhere.  This is the
// consensus-halt property stated as a test; a new branch that returns an error must fail here
// before it fails a fleet.
func TestHooksEveryMethodReturnsNilOnEveryBranch(t *testing.T) {
	for _, gate := range []bool{false, true} {
		k, ctx, h := setupHooks(t)
		if gate {
			enableRelease(t, k, ctx)
		}

		exercise := func() {
			require.NoError(t, h.AfterValidatorCreated(ctx, testValAddr))
			require.NoError(t, h.BeforeValidatorModified(ctx, testValAddr))
			require.NoError(t, h.AfterValidatorBonded(ctx, nil, testValAddr))
			require.NoError(t, h.AfterValidatorBeginUnbonding(ctx, nil, testValAddr))
			require.NoError(t, h.AfterValidatorRemoved(ctx, nil, testValAddr))
			require.NoError(t, h.BeforeDelegationCreated(ctx, nil, testValAddr))
			require.NoError(t, h.BeforeDelegationSharesModified(ctx, nil, testValAddr))
			require.NoError(t, h.BeforeDelegationRemoved(ctx, nil, testValAddr))
			require.NoError(t, h.AfterDelegationModified(ctx, nil, testValAddr))
			require.NoError(t, h.BeforeValidatorSlashed(ctx, testValAddr, sdkmath.LegacyZeroDec()))
			require.NoError(t, h.AfterUnbondingInitiated(ctx, 1))
		}

		exercise() // no row at all
		seedPioneerRow(k, ctx, "10.0.0.1")
		exercise() // row present; the unbond in here parks it
		exercise() // parked; covers empty-row and restore branches
	}
}

// THE MIRRORING DECISION, PINNED.  The parked store must stay out of mirroredStores: the enclave
// answers "is this pioneer a share-owner candidate" from the row's address alone, and that map
// also drives seed paging and the chain/enclave divergence audit -- adding the prefix there
// without teaching the enclave the store would fail every store-hash comparison (the PioneerJar
// membership lesson in enclave_seed_page.go).
func TestParkedStoreIsDeliberatelyNotMirrored(t *testing.T) {
	require.NotContains(t, keeper.MirroredStorePrefixesForTest(), types.ParkedExternalAddressKeyPrefix,
		"parking must stay chain-only; see the file comment in keeper/parked_external_address.go")
}

// A park/restore cycle flows every row write through SetIntervalPublicKeyID, whose accumulator
// arithmetic must land exactly on a from-scratch scan -- while the parked store's own writes,
// being unmirrored, must not disturb the audit either.  The audit HALTS on violation, so not
// panicking is the assertion.
func TestParkRestoreCycleKeepsAccumulatorsConsistent(t *testing.T) {
	k, ctx, h := setupHooks(t)
	enableRelease(t, k, ctx)
	seedPioneerRow(k, ctx, "10.0.0.1")

	k.MaintainStoreAccumulatorsForTest(ctx)

	require.NoError(t, h.AfterValidatorBeginUnbonding(ctx, nil, testValAddr))
	require.NoError(t, h.AfterValidatorBonded(ctx, nil, testValAddr))

	require.NotPanics(t, func() { k.AuditStoreAccumulatorsForTest(ctx.WithBlockHeight(25)) },
		"park (an overwrite), the parked-store writes, and restore (another overwrite) must leave "+
			"every mirrored accumulator equal to its data")
}
