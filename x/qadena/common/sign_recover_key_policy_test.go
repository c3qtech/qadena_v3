package common_test

import (
	"testing"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"
	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

func TestSignRecoverKeyAssertionModeFromParams(t *testing.T) {
	for _, tc := range []struct {
		name    string
		raw     uint32
		want    c.SignRecoverKeyAssertionMode
		enabled bool
		rejects bool
	}{
		{"unset reads as off", 0, c.SignRecoverKeyAssertionOff, false, false},
		{"audit", 1, c.SignRecoverKeyAssertionAudit, true, false},
		{"enforce", 2, c.SignRecoverKeyAssertionEnforce, true, true},
		// THE BACKSTOP.  A value this binary does not understand must read as OFF, never as a
		// licence to start rejecting signatures -- the failure direction matters more here than
		// almost anywhere, because enforcing wrongly fails every institutional recovery closed.
		// Params.Validate rejects these at the gate, so reaching here means a param written by a
		// newer binary than the one reading it.
		{"unknown reads as off", 3, c.SignRecoverKeyAssertionOff, false, false},
		{"far-future reads as off", 255, c.SignRecoverKeyAssertionOff, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := c.SignRecoverKeyAssertionModeFromParams(
				types.Params{SignRecoverKeyGuardianAssertionMode: tc.raw})
			if got != tc.want {
				t.Fatalf("mode %d: got %v want %v", tc.raw, got, tc.want)
			}
			if got.Enabled() != tc.enabled {
				t.Fatalf("mode %d: Enabled() = %v want %v", tc.raw, got.Enabled(), tc.enabled)
			}
			if got.Rejects() != tc.rejects {
				t.Fatalf("mode %d: Rejects() = %v want %v", tc.raw, got.Rejects(), tc.rejects)
			}
		})
	}
}

// Only enforce may reject.  Stated on its own because it is the invariant the audit mode exists to
// guarantee, and a one-character slip in Rejects() would silently turn audit into enforce.
func TestOnlyEnforceRejects(t *testing.T) {
	if c.SignRecoverKeyAssertionAudit.Rejects() {
		t.Fatal("audit must never reject -- it exists to measure the invariant on a live chain")
	}
	if c.SignRecoverKeyAssertionOff.Enabled() {
		t.Fatal("off must not even resolve the assertion")
	}
	if !c.SignRecoverKeyAssertionEnforce.Rejects() {
		t.Fatal("enforce must reject")
	}
}
