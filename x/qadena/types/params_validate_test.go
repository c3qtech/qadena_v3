package types_test

import (
	"strings"
	"testing"

	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

// An empty Params must validate: it is what DefaultParams() returns, and every loader substitutes
// its compiled-in default for an unset field.  Rejecting it would make a chain unstartable.
func TestParamsValidateEmpty(t *testing.T) {
	if err := (types.Params{}).Validate(); err != nil {
		t.Fatalf("empty params must be valid (every field is 'unset'), got %v", err)
	}
}

// THE CASE THIS FILE EXISTS FOR.
//
// update_credential_min_blocks_between_updates is one of only two signed params.  Its loader used to
// default only on == 0, so a negative slipped through and checkUpdateLimits' comparison
// (blockHeight - LastUpdateHeight < bound) became unsatisfiable -- the credential update rate limit
// was off entirely, silently, on an otherwise healthy chain.
func TestParamsValidateRejectsNegativeCooldown(t *testing.T) {
	p := types.Params{UpdateCredentialMinBlocksBetweenUpdates: -1}
	err := p.Validate()
	if err == nil {
		t.Fatal("a negative update cool-down must be rejected: it disables the rate limit rather than shortening it")
	}
	if !strings.Contains(err.Error(), "update_credential_min_blocks_between_updates") {
		t.Errorf("error should name the offending param, got %q", err)
	}
}

func TestParamsValidateRejectsNegativeWindow(t *testing.T) {
	if err := (types.Params{SuspiciousTransactionWindowSeconds: -60}).Validate(); err == nil {
		t.Fatal("a negative suspicious-transaction window must be rejected")
	}
}

// Above 100% the edit-distance bound permits any name of the same length to become any other, which
// is the correction check doing nothing.
func TestParamsValidateRejectsOverlargeEditPercent(t *testing.T) {
	if err := (types.Params{UpdateNameMaxEditDistancePercent: 101}).Validate(); err == nil {
		t.Fatal("an edit-distance percentage above 100 must be rejected")
	}
}

func TestParamsValidateRejectsTooManyChangedFields(t *testing.T) {
	if err := (types.Params{UpdateCredentialMaxChangedIdentityFields: 6}).Validate(); err == nil {
		t.Fatal("a changed-field cap above the number of identity fields must be rejected")
	}
}

func TestParamsValidateCoins(t *testing.T) {
	for _, tc := range []struct {
		name    string
		params  types.Params
		wantErr bool
	}{
		{"unset fee is fine", types.Params{}, false},
		{"good fee", types.Params{UpdateCredentialFee: "30php"}, false},
		{"good threshold", types.Params{SuspiciousTransactionThreshold: "10000usd"}, false},
		{"unparseable fee", types.Params{UpdateCredentialFee: "thirty pesos"}, true},
		{"zero threshold reports everything", types.Params{SuspiciousTransactionThreshold: "0usd"}, true},
		{"unparseable threshold", types.Params{SuspiciousTransactionThreshold: "lots"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.params.Validate()
			if tc.wantErr && err == nil {
				t.Error("expected a rejection, got none")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("expected acceptance, got %v", err)
			}
		})
	}
}

// A duplicate country makes the effective limit depend on which entry SelectThreshold read last --
// a silent, order-dependent policy rather than the one that was written down.
func TestParamsValidateRejectsDuplicateOverrideCountry(t *testing.T) {
	p := types.Params{
		SuspiciousTransactionThresholdOverrides: []types.SuspiciousThresholdOverride{
			{Country: "PH", Threshold: "500000php"},
			{Country: "ph", Threshold: "100000php"},
		},
	}
	if err := p.Validate(); err == nil {
		t.Fatal("two overrides for the same country (case-insensitively) must be rejected")
	}
}

func TestParamsValidateOverrideShape(t *testing.T) {
	for _, tc := range []struct {
		name     string
		override types.SuspiciousThresholdOverride
	}{
		{"empty country", types.SuspiciousThresholdOverride{Country: "", Threshold: "1usd"}},
		{"empty threshold", types.SuspiciousThresholdOverride{Country: "PH", Threshold: ""}},
		{"unparseable threshold", types.SuspiciousThresholdOverride{Country: "PH", Threshold: "loads"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := types.Params{SuspiciousTransactionThresholdOverrides: []types.SuspiciousThresholdOverride{tc.override}}
			if err := p.Validate(); err == nil {
				t.Error("expected a rejection, got none")
			}
		})
	}
}

// A good override set must still pass -- the checks above are worthless if they also reject the
// configuration this chain actually ships.
func TestParamsValidateAcceptsRealisticParams(t *testing.T) {
	p := types.Params{
		CreateCredentialFee:                      "30php",
		UpdateCredentialFee:                      "30php",
		SuspiciousTransactionThreshold:           "10000usd",
		SuspiciousTransactionWindowSeconds:       2592000,
		UpdateCredentialMinBlocksBetweenUpdates:  10000,
		UpdateNameMaxEditDistance:                2,
		UpdateNameMaxEditDistancePercent:         34,
		UpdateCredentialMaxChangedIdentityFields: 1,
		SuspiciousTransactionThresholdOverrides: []types.SuspiciousThresholdOverride{
			{Country: "PH", Threshold: "500000php"},
		},
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("a realistic param set must validate, got %v", err)
	}
}

// The assertion mode is an ENUM IN A uint32, so unlike every bool in this struct it has values
// that are simply wrong.  Nothing else here needs this check, which is exactly why it is easy to
// forget: a fat-fingered 3 in a governance proposal reads as "off" at the decision site, leaving
// institutional guardians unverified while the proposal appears to have switched enforcement on.
func TestParamsValidateRejectsUnknownAssertionMode(t *testing.T) {
	for _, mode := range []uint32{3, 4, 255} {
		err := (types.Params{SignRecoverKeyGuardianAssertionMode: mode}).Validate()
		if err == nil {
			t.Fatalf("assertion mode %d must be rejected: it is neither off, audit nor enforce", mode)
		}
		if !strings.Contains(err.Error(), "sign_recover_key_guardian_assertion_mode") {
			t.Fatalf("the error must name the field, got %v", err)
		}
	}
}

func TestParamsValidateAcceptsEveryAssertionMode(t *testing.T) {
	for _, mode := range []uint32{
		types.SignRecoverKeyAssertionOff,
		types.SignRecoverKeyAssertionAudit,
		types.SignRecoverKeyAssertionEnforce,
	} {
		if err := (types.Params{SignRecoverKeyGuardianAssertionMode: mode}).Validate(); err != nil {
			t.Fatalf("mode %d must be valid, got %v", mode, err)
		}
	}
}

// THE NO-MIGRATION CLAIM, ASSERTED RATHER THAN ASSUMED.
//
// ConsensusVersion moves 3 -> 4 for this field with no RegisterMigration handler, on the grounds
// that an absent field reads as 0 and 0 is defined as "behave exactly as before".  That is only
// true if gogoproto genuinely leaves it zero when it is missing from stored bytes -- so unmarshal
// params that predate the field and check.  If this ever fails, the upgrade silently changes
// behaviour on every existing chain.
func TestParamsWithoutAssertionModeReadsAsOff(t *testing.T) {
	// Params as an older binary would have written them: the field simply is not present.
	old := types.Params{UpdateCredentialMaxChangedIdentityFields: 1}
	b, err := old.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got types.Params
	if err := got.Unmarshal(b); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.SignRecoverKeyGuardianAssertionMode != types.SignRecoverKeyAssertionOff {
		t.Fatalf("params predating this field must read as off (0), got %d",
			got.SignRecoverKeyGuardianAssertionMode)
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("params predating this field must still validate, got %v", err)
	}
}

// DefaultParams() is what a chain starts from, and it must leave the gate OFF -- shipping it on
// would enforce an invariant that has never been measured against real traffic.
func TestDefaultParamsLeavesAssertionGateOff(t *testing.T) {
	if got := types.DefaultParams().SignRecoverKeyGuardianAssertionMode; got != types.SignRecoverKeyAssertionOff {
		t.Fatalf("the gate must ship off, got %d", got)
	}
}
