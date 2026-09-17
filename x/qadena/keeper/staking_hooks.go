package keeper

import (
	"context"

	sdkmath "cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"
	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

// Staking hooks: park a pioneer's published address while its validator is out of the bonded set,
// restore it when the validator returns.
//
// WHY.  A pioneer row's ExternalIPAddress is a security parameter, not contact information: the
// enclave's owner-candidate set for every NEW secret-share interval key is exactly the pioneer
// rows with a non-empty address (getAddressPublishedPioneers), and that set also sizes the share
// threshold and the enclave-identity vote quorum.  Nothing ever cleared it, so a validator that
// unbonded, was jailed, or was decommissioned kept counting as a share owner forever -- an owner
// with no stake behind it, and possibly no machine behind it either.
//
// WHY THE CHAIN RESTORES, RATHER THAN THE ENCLAVE REPUBLISHING.  The enclave's first publication
// rides a sealed once-only latch (PioneerIsValidator, set on the first proposed block and never
// re-armed), and its self-heal path refuses empty rows by design -- an empty row means "never
// bonded and proposed", and filling one from the correction path is how an unbonded node once
// became addressable with zero voting power (see the guard in planExternalAddressRepublish).  So
// once this hook empties the row, no enclave path will ever refill it: the parked value and the
// AfterValidatorBonded restore ARE the re-bond story.  A restored address may be stale -- a node
// that moved while unbonded -- and that is fine: the self-heal DOES correct non-empty rows that
// disagree with the node's sealed address.
//
// SCOPE.  Exclusion applies to FUTURE interval keys only.  Old keys' owner sets are
// chain-enforced to only grow (the proper-superset rule in MsgPioneerUpdatePublicKey), so a
// departed pioneer remains an owner of every key it already held -- shrinking those would be the
// wholesale re-share this feature deliberately avoids.
//
// EVERY HOOK RETURNS nil, UNCONDITIONALLY.  MultiStakingHooks propagates a non-nil return into
// the staking keeper's caller -- for the bonding transitions that is EndBlock, and an error there
// halts consensus.  Nothing this feature does is worth halting a chain over, so anomalies are
// events and logs, never errors.
//
// GATED on Params.ReleaseAddressOnUnbond (default false).  The gate is what makes shipping this
// binary consensus-safe: replaying pre-upgrade history, the hooks read the param as false and
// return before any state write, so historical app hashes reproduce.  It also covers the
// bootstrap ordering hazard for free -- genesis validators bond during staking's InitGenesis,
// BEFORE qadena's has run, and GetParams on an empty store returns the zero value, i.e. disabled.

var _ stakingtypes.StakingHooks = Hooks{}

// Hooks wrapper struct for the qadena keeper.
type Hooks struct {
	k Keeper
}

// Hooks returns the staking hooks for the qadena keeper.
func (k Keeper) Hooks() Hooks {
	return Hooks{k}
}

// AfterValidatorBeginUnbonding fires whenever a validator leaves the bonded set -- deliberate
// unbonding, downtime or double-sign jail, or falling out of max_validators all funnel through
// the same transition.
func (h Hooks) AfterValidatorBeginUnbonding(ctx context.Context, _ sdk.ConsAddress, valAddr sdk.ValAddress) error {
	h.k.parkPioneerExternalAddress(ctx, valAddr)
	return nil
}

// AfterValidatorBonded fires whenever a validator (re-)enters the bonded set.
func (h Hooks) AfterValidatorBonded(ctx context.Context, _ sdk.ConsAddress, valAddr sdk.ValAddress) error {
	h.k.restorePioneerExternalAddress(ctx, valAddr)
	return nil
}

// AfterValidatorRemoved deliberately does NOT delete the parked entry.  Removal happens when the
// unbonding period completes with no delegations left; the same pioneer key can create a fresh
// validator later, and its AfterValidatorBonded must still find the parked address -- the enclave
// will never republish the empty row itself (see the file comment), so a discarded parked value
// is a permanently unaddressable pioneer.
func (h Hooks) AfterValidatorRemoved(_ context.Context, _ sdk.ConsAddress, _ sdk.ValAddress) error {
	return nil
}

func (h Hooks) AfterValidatorCreated(_ context.Context, _ sdk.ValAddress) error {
	return nil
}

func (h Hooks) BeforeValidatorModified(_ context.Context, _ sdk.ValAddress) error {
	return nil
}

func (h Hooks) BeforeDelegationCreated(_ context.Context, _ sdk.AccAddress, _ sdk.ValAddress) error {
	return nil
}

func (h Hooks) BeforeDelegationSharesModified(_ context.Context, _ sdk.AccAddress, _ sdk.ValAddress) error {
	return nil
}

func (h Hooks) BeforeDelegationRemoved(_ context.Context, _ sdk.AccAddress, _ sdk.ValAddress) error {
	return nil
}

func (h Hooks) AfterDelegationModified(_ context.Context, _ sdk.AccAddress, _ sdk.ValAddress) error {
	return nil
}

func (h Hooks) BeforeValidatorSlashed(_ context.Context, _ sdk.ValAddress, _ sdkmath.LegacyDec) error {
	return nil
}

func (h Hooks) AfterUnbondingInitiated(_ context.Context, _ uint64) error {
	return nil
}

// pioneerRowForValidator resolves a validator to its pioneer row, or reports why it could not.
//
// The mapping is sdk.AccAddress(valAddr) == row.PubKID: a validator operator address re-encodes
// the same key bytes as the account that created the validator, convert_to_validator.sh creates
// the validator --from the pioneer key, and pioneer rows enforce PubKID == creator
// (msg_server_pioneer_update_interval_public_key_i_d.go, ErrNotRowOwner).  The MONIKER is
// deliberately not consulted: it is operator-set mutable free text with no consensus link to the
// row (config.toml's moniker need not even equal the validator's Description.Moniker -- see the
// warning in scripts/setup_env.sh).
func (k Keeper) pioneerRowForValidator(ctx context.Context, valAddr sdk.ValAddress) (types.IntervalPublicKeyID, string, bool) {
	pubKID := sdk.AccAddress(valAddr).String()
	row, found := k.GetIntervalPublicKeyIDByPubKID(ctx, pubKID)
	if !found || row.NodeType != types.PioneerNodeType {
		return types.IntervalPublicKeyID{}, pubKID, false
	}
	// The reverse index can outlive the row: RemoveIntervalPublicKeyID deletes only the primary
	// entry, so a removed row still resolves here.  Acting on that stale hit would send
	// SetIntervalPublicKeyID down its first-write path into the duplicate-PubKID panic -- and these
	// hooks run in staking EndBlock, where a panic is a consensus halt.  Require the primary row,
	// and return IT: the primary store is the one every other reader trusts.
	primary, found := k.GetIntervalPublicKeyID(ctx, row.NodeID, row.NodeType)
	if !found || primary.PubKID != pubKID {
		return types.IntervalPublicKeyID{}, pubKID, false
	}
	return primary, pubKID, true
}

// parkPioneerExternalAddress clears the pioneer row's address, keeping the value aside for the
// re-bond.  Never returns an error -- see the file comment.
func (k Keeper) parkPioneerExternalAddress(ctx context.Context, valAddr sdk.ValAddress) {
	if !k.GetParams(ctx).ReleaseAddressOnUnbond {
		return
	}
	sdkctx := sdk.UnwrapSDKContext(ctx)

	row, pubKID, ok := k.pioneerRowForValidator(ctx, valAddr)
	if !ok {
		// Expected for a validator that is not a qadena pioneer.  On a fleet where every
		// validator IS one, this event on an unbond means the mapping did not resolve and the
		// address was NOT cleared -- which is exactly what an operator needs to see.
		sdkctx.EventManager().EmitEvent(sdk.NewEvent(
			types.EventTypeUnbondPioneerRowNotFound,
			sdk.NewAttribute(types.AttributeExternalAddressPubKID, pubKID),
			sdk.NewAttribute(types.AttributeExternalAddressValoper, valAddr.String()),
		))
		return
	}

	// An already-empty row has nothing to park.  This is also what makes repeated jail cycles
	// safe: the first one parked the real address, and a second transition while still parked
	// must not overwrite that value with "".
	if row.ExternalIPAddress == "" {
		return
	}

	k.SetParkedExternalAddress(ctx, types.ParkedExternalAddress{
		PubKID:            pubKID,
		ExternalIPAddress: row.ExternalIPAddress,
	})

	parked := row.ExternalIPAddress
	row.ExternalIPAddress = ""
	// The full-service accessor, not a bare store write: it carries PreviousPubKID (a same-PubKID
	// rewrite keeps the existing pointer -- the DeactivateServiceProvider branch), maintains the
	// ByPubKID index, feeds the store-hash accumulator, and forwards the row to the local enclave
	// mirror so every node's enclave sees the pioneer leave the addressable set at this block.
	k.SetIntervalPublicKeyID(ctx, row)

	c.ContextInfo(sdkctx, "release-address: parked "+parked+" for pioneer "+row.NodeID+
		" ("+pubKID+") -- validator left the bonded set; excluded from NEW interval keys from here on")
	sdkctx.EventManager().EmitEvent(sdk.NewEvent(
		types.EventTypeExternalAddressParked,
		sdk.NewAttribute(types.AttributeExternalAddressPubKID, pubKID),
		sdk.NewAttribute(types.AttributeExternalAddressNodeID, row.NodeID),
		sdk.NewAttribute(types.AttributeExternalAddressValue, parked),
	))
}

// restorePioneerExternalAddress puts a parked address back on the row.  Never returns an error --
// see the file comment.
func (k Keeper) restorePioneerExternalAddress(ctx context.Context, valAddr sdk.ValAddress) {
	if !k.GetParams(ctx).ReleaseAddressOnUnbond {
		return
	}
	sdkctx := sdk.UnwrapSDKContext(ctx)

	pubKID := sdk.AccAddress(valAddr).String()
	parked, found := k.GetParkedExternalAddress(ctx, pubKID)
	if !found {
		// Nothing parked: a brand-new validator's first bond, or the feature was enabled after
		// the unbond.  First publication remains the enclave's (updateIsValidator, on the first
		// proposed block), so silence here is correct, not a failure.
		return
	}

	row, _, ok := k.pioneerRowForValidator(ctx, valAddr)
	if !ok {
		// A parked value with no row should be impossible (parking read the row), but a
		// deliberate row removal could produce it.  Keep the parked entry -- the row may come
		// back -- and say so.
		sdkctx.EventManager().EmitEvent(sdk.NewEvent(
			types.EventTypeUnbondPioneerRowNotFound,
			sdk.NewAttribute(types.AttributeExternalAddressPubKID, pubKID),
			sdk.NewAttribute(types.AttributeExternalAddressValoper, valAddr.String()),
		))
		return
	}

	if row.ExternalIPAddress != "" {
		// The operator republished manually while unbonded (a pioneer can always update its OWN
		// row).  Whatever is there now is newer than the parked value; restoring over it would be
		// the one way this feature could move a node backwards.  Discard the parked copy.
		k.RemoveParkedExternalAddress(ctx, pubKID)
		c.ContextInfo(sdkctx, "release-address: discarding parked "+parked.ExternalIPAddress+
			" for pioneer "+row.NodeID+" -- the row already carries "+row.ExternalIPAddress)
		sdkctx.EventManager().EmitEvent(sdk.NewEvent(
			types.EventTypeExternalAddressParkStale,
			sdk.NewAttribute(types.AttributeExternalAddressPubKID, pubKID),
			sdk.NewAttribute(types.AttributeExternalAddressNodeID, row.NodeID),
			sdk.NewAttribute(types.AttributeExternalAddressValue, parked.ExternalIPAddress),
		))
		return
	}

	row.ExternalIPAddress = parked.ExternalIPAddress
	k.SetIntervalPublicKeyID(ctx, row)
	k.RemoveParkedExternalAddress(ctx, pubKID)

	c.ContextInfo(sdkctx, "release-address: restored "+parked.ExternalIPAddress+" for pioneer "+
		row.NodeID+" ("+pubKID+") -- validator re-entered the bonded set.  If the node moved while"+
		" unbonded this value is stale; the enclave's self-heal corrects a non-empty row that"+
		" disagrees with the sealed address")
	sdkctx.EventManager().EmitEvent(sdk.NewEvent(
		types.EventTypeExternalAddressRestored,
		sdk.NewAttribute(types.AttributeExternalAddressPubKID, pubKID),
		sdk.NewAttribute(types.AttributeExternalAddressNodeID, row.NodeID),
		sdk.NewAttribute(types.AttributeExternalAddressValue, parked.ExternalIPAddress),
	))
}
