package types

import (
	"fmt"
	"strings"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// Params validation.
//
// WHAT THIS DEFENDS AGAINST.  Every numeric here is read by a loader that substitutes a compiled-in
// default when the value is zero, because proto3 cannot distinguish "unset" from "zero" and this
// module has no param migration.  That convention is safe for unset params and dangerous for wrong
// ones: a value that is merely *invalid* rather than zero sails past the loader and takes effect.
//
// The sharpest case is update_credential_min_blocks_between_updates, one of only two signed fields.
// Its loader defaults on == 0, so a NEGATIVE cool-down passes through intact, and checkUpdateLimits
// then evaluates
//
//	blockHeight - LastUpdateHeight < <negative>
//
// which is never true.  The credential-update rate limit is switched off permanently and silently,
// with the chain otherwise behaving normally.  Nothing logs it, because nothing considers it an
// error.
//
// WHY THIS FILE IS NEEDED AT ALL.  Params.Validate() existed but returned nil, and only genesis
// called it.  MsgUpdateParams went straight to SetParams, so the runtime path -- the one governance
// actually uses -- had no validation whatsoever.  Both now go through this.
//
// SCOPE.  Syntactic and range checks only, no pricefeed.  Whether "500000php" can be PRICED is a
// runtime question that already fails closed in ResolveThresholdToAttoUSD; whether it is a
// well-formed coin at all is a typo a reviewer should never have to catch by eye.

// Validate checks the params for values that would silently disable a control or fail later in a
// place that does not name them.
func (p Params) Validate() error {
	// Only two signed fields exist, and they are the only ones that can be negative at all.  Both
	// are treated as "use the default" when zero, so a negative is unambiguously a mistake rather
	// than an attempt to express something.
	if p.UpdateCredentialMinBlocksBetweenUpdates < 0 {
		return fmt.Errorf("update_credential_min_blocks_between_updates must not be negative, got %d "+
			"(a negative cool-down disables the credential update rate limit entirely)",
			p.UpdateCredentialMinBlocksBetweenUpdates)
	}
	if p.SuspiciousTransactionWindowSeconds < 0 {
		return fmt.Errorf("suspicious_transaction_window_seconds must not be negative, got %d",
			p.SuspiciousTransactionWindowSeconds)
	}

	// A percentage cap above 100 lets any name become any other name of the same length, which is
	// the edit-distance bound doing nothing.  Zero is "unset" and handled by the loader.
	if p.UpdateNameMaxEditDistancePercent > 100 {
		return fmt.Errorf("update_name_max_edit_distance_percent must be at most 100, got %d",
			p.UpdateNameMaxEditDistancePercent)
	}

	// Not an error -- WithDefaults clamps it, since a cap above the number of identity fields
	// permits nothing extra -- but worth refusing at the gate so the stored value means what it
	// says.  MaxIdentityFieldCount lives in common/, which imports this package, so it is spelled
	// out here rather than imported back.
	const maxIdentityFieldCount = 5 // first/middle/last name, birthdate, gender
	if p.UpdateCredentialMaxChangedIdentityFields > maxIdentityFieldCount {
		return fmt.Errorf("update_credential_max_changed_identity_fields must be at most %d, got %d",
			maxIdentityFieldCount, p.UpdateCredentialMaxChangedIdentityFields)
	}

	// AN ENUM LIVING IN A uint32, so unlike every bool here it HAS an invalid value.  No bool in
	// this struct is validated because there is nothing a bool can be that is wrong; this field
	// needs the check precisely because the type is wider than the meaning.
	//
	// Getting it wrong is not loud: SignRecoverKeyAssertionModeFromParams treats any unrecognised
	// value as off, so a fat-fingered 3 in a gov proposal would silently leave institutional
	// guardians unverified while the proposal read as though it had switched enforcement on.
	if p.SignRecoverKeyGuardianAssertionMode > SignRecoverKeyAssertionEnforce {
		return fmt.Errorf("sign_recover_key_guardian_assertion_mode must be 0 (off), 1 (audit) or 2 (enforce), got %d",
			p.SignRecoverKeyGuardianAssertionMode)
	}

	// Coin-shaped strings.  Empty means "unset" for all of these and the loaders supply a default,
	// so only a non-empty value is checked.
	for _, f := range []struct {
		name  string
		value string
	}{
		{"create_credential_fee", p.CreateCredentialFee},
		{"create_bulk_credentials_fee", p.CreateBulkCredentialsFee},
		{"update_credential_fee", p.UpdateCredentialFee},
		{"suspicious_transaction_threshold", p.SuspiciousTransactionThreshold},
	} {
		if err := validatePositiveCoin(f.name, f.value); err != nil {
			return err
		}
	}

	// A duplicate country would make the effective threshold depend on which entry SelectThreshold
	// happened to read last, and an unparseable one would fail closed at scan time -- refusing every
	// transfer by a sender in that jurisdiction, with the cause several layers away.
	// A slice of VALUES, not pointers, so there is no nil entry to guard against.
	// A slice of VALUES, not pointers, so there is no nil entry to guard against.
	seen := make(map[string]struct{}, len(p.SuspiciousTransactionThresholdOverrides))
	for i, override := range p.SuspiciousTransactionThresholdOverrides {
		country := strings.ToUpper(strings.TrimSpace(override.Country))
		if country == "" {
			return fmt.Errorf("suspicious_transaction_threshold_overrides[%d] has an empty country", i)
		}
		if _, dup := seen[country]; dup {
			return fmt.Errorf("suspicious_transaction_threshold_overrides has more than one entry for %s", country)
		}
		seen[country] = struct{}{}

		// Required, not optional: unlike the fees above, an override exists only to carry a
		// threshold, so an empty one is always a mistake.
		if strings.TrimSpace(override.Threshold) == "" {
			return fmt.Errorf("suspicious_transaction_threshold_overrides[%s] has an empty threshold", country)
		}
		if err := validatePositiveCoin(
			"suspicious_transaction_threshold_overrides["+country+"]", override.Threshold); err != nil {
			return err
		}
	}

	return nil
}

// validatePositiveCoin accepts an empty value as "unset" and otherwise requires a parseable,
// strictly positive coin.  Zero is rejected rather than defaulted: a zero threshold would report
// every transfer and a zero fee is better expressed by leaving the param out.
func validatePositiveCoin(name, value string) error {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	coin, err := sdk.ParseCoinNormalized(value)
	if err != nil {
		return fmt.Errorf("%s %q is not a valid coin: %w", name, value, err)
	}
	if !coin.Amount.IsPositive() {
		return fmt.Errorf("%s %q must be positive", name, value)
	}
	return nil
}

// The three states of sign_recover_key_guardian_assertion_mode.
//
// Declared in types/ rather than common/ because Validate() above is the one place that must
// reject an out-of-range value, and common/ imports this package rather than the other way round.
const (
	// SignRecoverKeyAssertionOff is the proto3 zero, and therefore what an un-upgraded chain and
	// any params predating this field read as: do not look at the assertion at all.
	SignRecoverKeyAssertionOff uint32 = 0
	// SignRecoverKeyAssertionAudit resolves the assertion and LOGS a mismatch, but still accepts
	// the signature.  This is the state the whole design exists to make possible: the scheme rests
	// on the guardian's hash matching the one issuance produced, and enforcing an unproven
	// invariant would fail every institutional signature closed.
	SignRecoverKeyAssertionAudit uint32 = 1
	// SignRecoverKeyAssertionEnforce rejects a mismatch.  Only safe once audit has shown real
	// traffic matching.
	SignRecoverKeyAssertionEnforce uint32 = 2
)
