package types

// Events emitted by the staking hooks (keeper/staking_hooks.go) -- the module's first events.
//
// The hooks are FORBIDDEN from returning errors: MultiStakingHooks propagates a non-nil return
// into staking's EndBlock, which is a consensus halt.  Events are therefore the only signal an
// operator gets that a park/restore happened, or that one was expected and could not proceed --
// so each anomaly gets its own type rather than an attribute on a shared one, and a missing event
// is itself diagnostic.
const (
	// A pioneer row's address was moved into the parked store because its validator left the
	// bonded set.  From this block on the pioneer is not a share-owner candidate for NEW interval
	// keys and peers are told nothing to dial.
	EventTypeExternalAddressParked = "external_address_parked"

	// A parked address was written back into the pioneer row because its validator re-entered the
	// bonded set.  The restored value may be stale if the node moved while unbonded; the enclave's
	// self-heal corrects a non-empty row that disagrees with the node's sealed address.
	EventTypeExternalAddressRestored = "external_address_restored"

	// A validator re-bonded while its row ALREADY held an address -- the operator republished
	// manually while unbonded.  The parked value is discarded rather than restored: it is older
	// than what is on the row, and clobbering a newer address with it would be the one way this
	// feature could move a node backwards.
	EventTypeExternalAddressParkStale = "external_address_park_stale"

	// A validator left or entered the bonded set but no pioneer row exists under its operator
	// account.  Expected for any validator that is not a qadena pioneer; on a fleet where every
	// validator is one, this event on an unbond is the signal that the PubKID mapping did not
	// resolve and the address was NOT cleared.
	EventTypeUnbondPioneerRowNotFound = "unbond_pioneer_row_not_found"

	AttributeExternalAddressPubKID  = "pub_k_id"
	AttributeExternalAddressNodeID  = "node_id"
	AttributeExternalAddressValue   = "external_ip_address"
	AttributeExternalAddressValoper = "validator_operator"
)
