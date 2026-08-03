package common

import (
	"testing"
	"time"

	cosmosmath "cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

func attoUSD(n int64) sdk.Coin {
	return sdk.NewCoin(types.AttoUSDFiatDenom, cosmosmath.NewInt(n))
}

func transferAt(unix int64, dst string, usd int64) *types.EncryptableScanTransfer {
	return &types.EncryptableScanTransfer{
		UnixTime:            unix,
		DestinationWalletID: dst,
		USDCoinAmount:       attoUSD(usd),
		CoinAmount:          sdk.NewCoin("qdn", cosmosmath.NewInt(usd)),
	}
}

// An unset param must read as "use the default", never as a literal zero.  A zero window would put
// the cutoff at the current instant and expire every entry on arrival, quietly turning the
// aggregate rule off -- the failure mode is invisible, because scanning still appears to run.
func TestSuspiciousPolicyFromParamsSubstitutesDefaults(t *testing.T) {
	policy := SuspiciousPolicyFromParams(types.Params{})

	if policy.Window != DefaultSuspiciousWindow {
		t.Errorf("unset window = %v, want the default %v", policy.Window, DefaultSuspiciousWindow)
	}
	if policy.AllowTransferWithoutEKYC {
		t.Error("unset allow_transfer_without_ekyc must read as ENFORCING; proto3 cannot tell unset from false, so the flag has to be named such that false is the safe state")
	}
	if got := SuspiciousThresholdFromParams(types.Params{}); got != DefaultSuspiciousThreshold {
		t.Errorf("unset threshold = %q, want %q", got, DefaultSuspiciousThreshold)
	}

	// a negative window is nonsense and must not produce a cutoff in the future
	if p := SuspiciousPolicyFromParams(types.Params{SuspiciousTransactionWindowSeconds: -1}); p.Window != DefaultSuspiciousWindow {
		t.Errorf("negative window = %v, want the default", p.Window)
	}

	set := SuspiciousPolicyFromParams(types.Params{
		SuspiciousTransactionWindowSeconds: 3600,
		AllowTransferWithoutEkyc:           true,
	})
	if set.Window != time.Hour || !set.AllowTransferWithoutEKYC {
		t.Errorf("configured values not honoured: %+v", set)
	}
}

func TestPruneExpired(t *testing.T) {
	now := int64(1_000_000)
	window := int64(3600)
	cutoff := now - window

	transfers := []*types.EncryptableScanTransfer{
		transferAt(cutoff-1, "dst", 1), // just outside
		transferAt(cutoff, "dst", 2),   // exactly on the boundary -- inside
		transferAt(now, "dst", 3),      // current
		nil,                            // must not panic
	}

	kept := PruneExpired(transfers, cutoff)

	if len(kept) != 2 {
		t.Fatalf("kept %d entries, want 2", len(kept))
	}
	if kept[0].UnixTime != cutoff || kept[1].UnixTime != now {
		t.Errorf("wrong entries kept: %v, %v", kept[0].UnixTime, kept[1].UnixTime)
	}

	// an entirely stale history collapses to empty rather than to nil-with-capacity surprises
	allStale := []*types.EncryptableScanTransfer{transferAt(0, "dst", 1), transferAt(1, "dst", 2)}
	if got := PruneExpired(allStale, cutoff); len(got) != 0 {
		t.Errorf("stale history kept %d entries, want 0", len(got))
	}

	if got := PruneExpired(nil, cutoff); len(got) != 0 {
		t.Errorf("nil history produced %d entries", len(got))
	}
}

// Pruning must not alias the caller's backing array: the result is written back to the store, and
// an in-place filter that shared memory would be easy to get subtly wrong.
func TestPruneExpiredDoesNotMutateInput(t *testing.T) {
	transfers := []*types.EncryptableScanTransfer{
		transferAt(10, "a", 1),
		transferAt(20, "b", 2),
	}

	PruneExpired(transfers, 15)

	if len(transfers) != 2 || transfers[0].UnixTime != 10 || transfers[1].UnixTime != 20 {
		t.Error("PruneExpired modified the slice it was given")
	}
}

func TestAggregateByDestination(t *testing.T) {
	usd := AggregateByDestination([]*types.EncryptableScanTransfer{
		transferAt(1, "alice", 100),
		transferAt(2, "bob", 30),
		transferAt(3, "alice", 50),
		nil,
	})

	if got := usd["alice"]; !got.Amount.Equal(cosmosmath.NewInt(150)) {
		t.Errorf("alice usd total = %s, want 150", got.Amount)
	}
	if got := usd["bob"]; !got.Amount.Equal(cosmosmath.NewInt(30)) {
		t.Errorf("bob usd total = %s, want 30", got.Amount)
	}
	// destinations must not be pooled -- the rule is per source/destination PAIR
	if usd["alice"].Amount.Equal(usd["bob"].Amount) {
		t.Error("totals for different destinations collapsed together")
	}
}

// A window can hold several denominations for one destination: transfer-funds accepts erc20
// denominations, and a bank send carries sdk.Coins.  Aggregation must survive that.  It previously
// did not -- a per-destination token total was summed with sdk.Coin.Add, which panics when the
// denominations differ, so the second denomination to any destination brought the enclave down.
func TestAggregateByDestinationMixedDenoms(t *testing.T) {
	mixed := []*types.EncryptableScanTransfer{
		{
			UnixTime:            1,
			DestinationWalletID: "alice",
			USDCoinAmount:       attoUSD(100),
			CoinAmount:          sdk.NewCoin("qdn", cosmosmath.NewInt(100)),
		},
		{
			UnixTime:            2,
			DestinationWalletID: "alice",
			USDCoinAmount:       attoUSD(50),
			CoinAmount:          sdk.NewCoin("erc20/abc", cosmosmath.NewInt(7)),
		},
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("mixed denominations panicked: %v", r)
		}
	}()

	usd := AggregateByDestination(mixed)
	if got := usd["alice"]; !got.Amount.Equal(cosmosmath.NewInt(150)) {
		t.Errorf("alice usd total = %s, want 150 (USD is summable across denominations)", got.Amount)
	}
}

func TestDropDestination(t *testing.T) {
	transfers := []*types.EncryptableScanTransfer{
		transferAt(1, "alice", 1),
		transferAt(2, "bob", 2),
		transferAt(3, "alice", 3),
	}

	kept := DropDestination(transfers, "alice")

	if len(kept) != 1 || kept[0].DestinationWalletID != "bob" {
		t.Errorf("DropDestination left %d entries, want only bob's", len(kept))
	}
}

func TestCountriesFromDetails(t *testing.T) {
	tests := []struct {
		name      string
		residency string
		citizen   string
		want      []string
	}{
		{"single of each, same country", "PH", "PH", []string{"PH"}},
		{"residency and citizenship differ", "US", "PH", []string{"US", "PH"}},
		{"multiple residencies", "US,AU", "PH", []string{"US", "AU", "PH"}},
		{"whitespace and case", " ph , us ", "au", []string{"PH", "US", "AU"}},
		{"empty citizenship", "PH", "", []string{"PH"}},
		{"both empty", "", "", []string{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CountriesFromDetails(&types.EncryptablePersonalInfoDetails{
				Residency:   tt.residency,
				Citizenship: tt.citizen,
			})
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("got %v, want %v", got, tt.want)
				}
			}
		})
	}

	if got := CountriesFromDetails(nil); got != nil {
		t.Errorf("nil details produced %v", got)
	}
}

// The security property: declaring another jurisdiction may only ever TIGHTEN a sender's limit.
//
// Residency and Citizenship are free fields in the credential update policy -- no edit-distance
// bound, no rate limit -- so if the highest or the first-listed threshold won, a sender could raise
// their own reporting limit by editing an unconstrained field.
func TestSelectThresholdTakesTheMostRestrictive(t *testing.T) {
	table := []*types.ScanCountryThreshold{
		{Country: "PH", ThresholdAttoUSD: "8000"},
		{Country: "US", ThresholdAttoUSD: "10000"},
		{Country: "AU", ThresholdAttoUSD: "9000"},
	}
	def := cosmosmath.NewInt(10000)

	tests := []struct {
		name      string
		countries []string
		want      int64
	}{
		{"single listed country", []string{"PH"}, 8000},
		{"lowest of several wins", []string{"US", "AU", "PH"}, 8000},
		{"order does not matter", []string{"PH", "US"}, 8000},
		{"adding a looser country cannot loosen", []string{"PH", "US", "AU"}, 8000},
		{"unlisted country falls back to the default", []string{"JP"}, 10000},
		{"no countries at all falls back", []string{}, 10000},
		{"listed plus unlisted uses the listed one", []string{"JP", "PH"}, 8000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SelectThreshold(tt.countries, table, def); !got.Equal(cosmosmath.NewInt(tt.want)) {
				t.Errorf("SelectThreshold(%v) = %s, want %d", tt.countries, got, tt.want)
			}
		})
	}
}

// A malformed or zero entry must be skipped, not treated as a threshold of zero -- zero would flag
// every transfer that sender made.  A bad param should degrade to the default, not to chaos.
func TestSelectThresholdIgnoresUnusableEntries(t *testing.T) {
	def := cosmosmath.NewInt(10000)

	table := []*types.ScanCountryThreshold{
		{Country: "PH", ThresholdAttoUSD: "not-a-number"},
		{Country: "US", ThresholdAttoUSD: "0"},
		{Country: "AU", ThresholdAttoUSD: "-5"},
		nil,
	}

	for _, countries := range [][]string{{"PH"}, {"US"}, {"AU"}, {"PH", "US", "AU"}} {
		if got := SelectThreshold(countries, table, def); !got.Equal(def) {
			t.Errorf("SelectThreshold(%v) = %s, want the default %s", countries, got, def)
		}
	}
}
