package common

// The AML policy behind ScanTransaction: how long the rolling window is, which jurisdiction's
// reporting threshold applies to a given sender, and whether a wallet with no eKYC data may send at
// all.
//
// Everything here must be a pure function of its arguments, for the same reason as
// credential_policy.go: it runs inside the enclave on every validator, and the verdict decides
// whether the transfer is REJECTED.  Two nodes disagreeing is a consensus failure, not a bad
// report.  In particular nothing here may read the wall clock -- the caller supplies block time.

import (
	"errors"
	"strings"
	"time"

	cosmosmath "cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

const (
	// DefaultSuspiciousThreshold is the fallback reporting limit, used when a chain has not
	// configured one and for any sender whose jurisdictions are not listed in the overrides.
	DefaultSuspiciousThreshold = "10000usd"

	// DefaultSuspiciousWindow is the rolling period the aggregate rule looks back over.  Thirty
	// days is the usual structuring-detection window; before this existed the aggregate was a
	// LIFETIME total, which is a different rule and eventually flags ordinary users.
	DefaultSuspiciousWindow = 30 * 24 * time.Hour
)

// ErrNoJurisdiction is returned when a sender has no usable country and the chain requires eKYC.
var ErrNoJurisdiction = errors.New("sender has no residency or citizenship on record")

type SuspiciousPolicy struct {
	Window time.Duration

	// AllowTransferWithoutEKYC mirrors the param of the same name.  False -- the proto3 zero, and
	// so also the value an un-upgraded chain reports -- is the ENFORCING state.
	AllowTransferWithoutEKYC bool

	// BlockTransferWithoutOptInReason decides what happens to a reportable transfer whose sender
	// supplied no --opt-in-reason.
	//
	// False (the default, and the proto3 zero): REPORT IT ANYWAY, with DefaultOptInReason standing
	// in for the missing text, and let the transfer proceed.  A report the regulator receives is
	// worth more than a transfer that silently did not happen, and refusing produced neither.
	//
	// True: refuse instead, which is what this chain did before the flag existed -- every report
	// was self-selected, so a sender unwilling to be named simply stayed under the limit and the
	// regulator saw nothing at all.
	//
	// Note the direction: here false is the MORE INFORMATIVE state, not merely the laxer one, so
	// the usual "an unset AML param must not switch a control off" reading does not apply.  An
	// un-upgraded chain gets more reports than before, never fewer.
	BlockTransferWithoutOptInReason bool
}

// DefaultOptInReason stands in when a reportable transfer carries no reason.  It is deliberately
// bland and fixed: it is written into a regulator-encrypted report, so it must never echo anything
// the sender supplied.
const DefaultOptInReason = "No reason provided"

// OptInReasonOrDefault keeps the substitution in one place, so no call site can file a report with
// an empty reason field.
func OptInReasonOrDefault(reason string) string {
	if strings.TrimSpace(reason) == "" {
		return DefaultOptInReason
	}
	return reason
}

// SuspiciousPolicyFromParams reads the policy, substituting compiled-in defaults for anything unset.
//
// Follows the convention established by UpdateLimitsFromParams: a zero is indistinguishable from an
// unset param on a chain whose genesis predates the field, so zero means "use the default".  For
// this policy that reading is not merely convenient, it is the only safe one -- a literal zero
// window would expire every entry immediately and silently disable the aggregate rule.
func SuspiciousPolicyFromParams(p types.Params) SuspiciousPolicy {
	policy := SuspiciousPolicy{
		Window:                          time.Duration(p.SuspiciousTransactionWindowSeconds) * time.Second,
		AllowTransferWithoutEKYC:        p.AllowTransferWithoutEkyc,
		BlockTransferWithoutOptInReason: p.BlockTransferWithoutOptInReason,
	}
	if policy.Window <= 0 {
		policy.Window = DefaultSuspiciousWindow
	}
	return policy
}

// SuspiciousThresholdFromParams returns the chain-wide default threshold as written, e.g.
// "10000usd".  Converting it to a comparable unit needs the pricefeed and therefore happens in the
// keeper, not here and not in the enclave.
func SuspiciousThresholdFromParams(p types.Params) string {
	if strings.TrimSpace(p.SuspiciousTransactionThreshold) == "" {
		return DefaultSuspiciousThreshold
	}
	return p.SuspiciousTransactionThreshold
}

// CountriesFromDetails returns the jurisdictions a credential holder belongs to: the union of
// residency and citizenship.
//
// Both fields are comma-separated alpha-2 lists, normalized through gountries when the credential
// was created.  Both are included because both are grounds for a jurisdiction to claim reporting
// authority, and because SelectThreshold takes the most restrictive -- see the note there.
//
// Order is residency first, then citizenship, with duplicates dropped, so the result is
// deterministic for a given credential.
func CountriesFromDetails(pd *types.EncryptablePersonalInfoDetails) []string {
	if pd == nil {
		return nil
	}

	seen := make(map[string]bool)
	countries := make([]string, 0, 4)

	for _, field := range []string{pd.Residency, pd.Citizenship} {
		for _, raw := range strings.Split(field, ",") {
			cc := strings.ToUpper(strings.TrimSpace(raw))
			if cc == "" || seen[cc] {
				continue
			}
			seen[cc] = true
			countries = append(countries, cc)
		}
	}

	return countries
}

// SelectThreshold picks the reporting limit for a sender belonging to `countries`.
//
// THE MOST RESTRICTIVE WINS.  This is a security property, not a tie-break: Citizenship and
// Residency are free fields in the credential update policy -- changeable with no edit-distance
// bound and no rate limit (see ClassifyPersonalInfoUpdate, UpdateKindFreeFieldsOnly).  If the
// highest or the first-listed threshold won, a sender could raise their own reporting limit by
// editing an unconstrained field.  Taking the minimum means declaring an additional jurisdiction
// can only ever tighten the limit.
//
// A sender whose countries are all unlisted gets the chain default.  Entries with an unparseable
// threshold are skipped rather than treated as zero: zero would flag every transfer, and a
// malformed param should not be able to do that.
func SelectThreshold(countries []string, table []*types.ScanCountryThreshold, defaultThreshold cosmosmath.Int) cosmosmath.Int {
	byCountry := make(map[string]cosmosmath.Int, len(table))
	for _, entry := range table {
		if entry == nil {
			continue
		}
		amount, ok := cosmosmath.NewIntFromString(entry.ThresholdAttoUSD)
		if !ok || amount.IsNil() || !amount.IsPositive() {
			continue
		}
		byCountry[strings.ToUpper(strings.TrimSpace(entry.Country))] = amount
	}

	selected := defaultThreshold
	found := false

	for _, cc := range countries {
		amount, ok := byCountry[cc]
		if !ok {
			continue
		}
		if !found || amount.LT(selected) {
			selected = amount
			found = true
		}
	}

	return selected
}

// PruneExpired drops entries that fall outside the rolling window.
//
// The boundary is inclusive of the cutoff instant: an entry recorded exactly `window` ago is still
// inside the window.  Comparison is on the BLOCK time recorded with each entry, so every validator
// prunes identically.
//
// Returns a new slice rather than filtering in place, because the caller writes the result back to
// the store and an aliased backing array makes that easy to get wrong.
func PruneExpired(transfers []*types.EncryptableScanTransfer, cutoffUnix int64) []*types.EncryptableScanTransfer {
	kept := make([]*types.EncryptableScanTransfer, 0, len(transfers))
	for _, tf := range transfers {
		if tf == nil || tf.UnixTime < cutoffUnix {
			continue
		}
		kept = append(kept, tf)
	}
	return kept
}

// AggregateByDestination sums a window's transfers per destination wallet, in attoUSD.
//
// USD is the only unit that can be summed here.  A window may hold entries in several
// denominations -- transfer-funds accepts erc20 denominations, and a bank send carries sdk.Coins,
// which can move more than one at once -- and sdk.Coin.Add PANICS when the denominations differ.
// An earlier version of this function also returned a per-destination token total and would panic
// the moment a wallet sent two denominations to the same destination inside one window.
//
// Nothing is lost by dropping it: the threshold is denominated in USD, so the decision only ever
// used the USD figure, and a token total across mixed denominations is not a meaningful number to
// report anyway.  A report that needs to state a token amount uses the transfer that triggered it.
//
// Each entry contributes the fiat value computed at the rate in force when it was scanned, which is
// why that value is stored rather than recomputed.
func AggregateByDestination(transfers []*types.EncryptableScanTransfer) map[string]sdk.Coin {
	usd := make(map[string]sdk.Coin)

	for _, tf := range transfers {
		if tf == nil {
			continue
		}

		running, seen := usd[tf.DestinationWalletID]
		if !seen {
			running = sdk.NewCoin(types.AttoUSDFiatDenom, cosmosmath.NewInt(0))
		}
		usd[tf.DestinationWalletID] = running.Add(tf.USDCoinAmount)
	}

	return usd
}

// DropDestination removes every entry for one destination, used after a tripped aggregate has been
// reported so the pair starts fresh instead of re-reporting on every subsequent transfer.
func DropDestination(transfers []*types.EncryptableScanTransfer, dstWalletID string) []*types.EncryptableScanTransfer {
	kept := make([]*types.EncryptableScanTransfer, 0, len(transfers))
	for _, tf := range transfers {
		if tf == nil || tf.DestinationWalletID == dstWalletID {
			continue
		}
		kept = append(kept, tf)
	}
	return kept
}
