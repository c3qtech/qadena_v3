package common

// The change policy for MsgUpdateCredential.  Everything in this file must be a pure function of
// its arguments: it runs inside the enclave on every validator, so a disagreement between two
// nodes is a consensus failure, not a bad UX.  Three rules follow from that:
//
//   - no floating point (integer comparisons only),
//   - no golang.org/x/text (its Unicode tables are module-versioned; the stdlib's move only with
//     the toolchain, which UpdateCredentialPolicyVersion is there to make visible),
//   - runes, not bytes, everywhere, or "ñ" counts as two edits.
//
// The eKYC server imports this same code to pre-validate a correction before the user spends a
// transaction, which is why it lives in common rather than in the enclave.

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"

	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

// The identity-bearing fields, i.e. the ones CreateCredentialHash reads.  Citizenship and
// Residency are deliberately absent: they are free fields, changeable in any combination.
const (
	UpdateFieldFirstName  = "FirstName"
	UpdateFieldMiddleName = "MiddleName"
	UpdateFieldLastName   = "LastName"
	UpdateFieldBirthdate  = "Birthdate"
	UpdateFieldGender     = "Gender"
)

type UpdateKind int

const (
	// nothing hash-contributing changed; only Citizenship and/or Residency moved
	UpdateKindFreeFieldsOnly UpdateKind = iota
	// one hash-contributing field moved by an amount that looks like a data-entry fix
	UpdateKindCorrection
	// one hash-contributing field was replaced wholesale by a recognised life event
	// (marriage/divorce surname change)
	UpdateKindLifeEvent
)

func (k UpdateKind) String() string {
	switch k {
	case UpdateKindFreeFieldsOnly:
		return "free-fields-only"
	case UpdateKindCorrection:
		return "correction"
	case UpdateKindLifeEvent:
		return "life-event"
	default:
		return "unknown(" + strconv.Itoa(int(k)) + ")"
	}
}

type UpdateVerdict struct {
	Kind UpdateKind
	// the single hash-contributing field that changed, or "" for UpdateKindFreeFieldsOnly
	ChangedField string
	// whether CreateCredentialHash(old) != CreateCredentialHash(new), i.e. whether the caller
	// must record a new identity alias
	HashChanged bool
}

// UpdatePolicy is the tunable part of the policy, populated from module params.  It is a plain
// struct of ints and bools so the engine stays testable without a chain.
type UpdatePolicy struct {
	// absolute cap on the restricted edit distance between an old and a corrected name
	MaxEditDistance int
	// relative cap, in percent of the longer name: dist*100 <= MaxEditDistancePercent*runeLen.
	// Without it a two-edit budget would rewrite a three-letter name entirely.
	MaxEditDistancePercent int
	// how far a birth year may move when nothing else about the date does
	MaxYearDelta int
	// whether a surname may be replaced wholesale (marriage/divorce) rather than only corrected
	AllowLastNameLifeEvent bool
	// whether Gender may change at all; a jurisdiction can disable it by param rather than by fork
	AllowGenderChange bool
}

// Compiled-in defaults.  DefaultParams() returns an empty Params{} and this codebase has no param
// migration, so a chain that predates these params reads every numeric as 0 — which without
// WithDefaults would mean "reject every correction".
const (
	DefaultUpdateNameMaxEditDistance        = 2
	DefaultUpdateNameMaxEditDistancePercent = 34
	DefaultUpdateBirthdateMaxYearDelta      = 1
)

// DefaultUpdatePolicy is the policy a chain gets when it sets none of the params.
func DefaultUpdatePolicy() UpdatePolicy {
	return UpdatePolicy{
		MaxEditDistance:        DefaultUpdateNameMaxEditDistance,
		MaxEditDistancePercent: DefaultUpdateNameMaxEditDistancePercent,
		MaxYearDelta:           DefaultUpdateBirthdateMaxYearDelta,
		AllowLastNameLifeEvent: true,
		AllowGenderChange:      true,
	}
}

// WithDefaults substitutes the compiled-in default for any numeric left at zero.  The booleans
// are left alone: false is indistinguishable from unset, and the safe reading of "unset" for a
// gate is "closed".  The params loader must therefore set the two Allow* flags explicitly.
func (p UpdatePolicy) WithDefaults() UpdatePolicy {
	d := DefaultUpdatePolicy()
	if p.MaxEditDistance == 0 {
		p.MaxEditDistance = d.MaxEditDistance
	}
	if p.MaxEditDistancePercent == 0 {
		p.MaxEditDistancePercent = d.MaxEditDistancePercent
	}
	if p.MaxYearDelta == 0 {
		p.MaxYearDelta = d.MaxYearDelta
	}
	return p
}

// UpdateLimits is the rate-limiting half of the policy.  It is not consulted by
// ClassifyPersonalInfoUpdate -- it needs the enclave's identity-history record and the block
// height, neither of which is a function of the plaintext diff -- but it is loaded from params
// the same way and so lives here.
type UpdateLimits struct {
	// cap on entries in a credential's alias list.  The list holds the original identity plus
	// one hash per hash-changing update, so the lifetime update budget is this minus one.
	MaxIdentityAliases uint32
	MaxLifeEvents      uint32
	// cool-down between updates, measured against the height the keeper stamped into the
	// enclave request.  The enclave has no block height of its own.
	MinBlocksBetweenUpdates int64
}

const (
	DefaultUpdateCredentialFee                     = "30php"
	DefaultUpdateCredentialMaxIdentityAliases      = 4
	DefaultUpdateCredentialMaxLifeEvents           = 2
	DefaultUpdateCredentialMinBlocksBetweenUpdates = 10000
)

// UpdatePolicyFromParams reads the tunable policy out of the module params, substituting the
// compiled-in default for any numeric the chain has not set.  The two Allow* gates are taken
// verbatim: proto3 cannot tell false from unset, so an unset gate reads as closed, and config.yml
// must set them explicitly for a chain that wants those transitions.
func UpdatePolicyFromParams(p types.Params) UpdatePolicy {
	return UpdatePolicy{
		MaxEditDistance:        int(p.UpdateNameMaxEditDistance),
		MaxEditDistancePercent: int(p.UpdateNameMaxEditDistancePercent),
		MaxYearDelta:           int(p.UpdateBirthdateMaxYearDelta),
		AllowLastNameLifeEvent: p.UpdateCredentialAllowLastNameLifeEvent,
		AllowGenderChange:      p.UpdateCredentialAllowGenderChange,
	}.WithDefaults()
}

func UpdateLimitsFromParams(p types.Params) UpdateLimits {
	limits := UpdateLimits{
		MaxIdentityAliases:      p.UpdateCredentialMaxIdentityAliases,
		MaxLifeEvents:           p.UpdateCredentialMaxLifeEvents,
		MinBlocksBetweenUpdates: p.UpdateCredentialMinBlocksBetweenUpdates,
	}
	if limits.MaxIdentityAliases == 0 {
		limits.MaxIdentityAliases = DefaultUpdateCredentialMaxIdentityAliases
	}
	if limits.MaxLifeEvents == 0 {
		limits.MaxLifeEvents = DefaultUpdateCredentialMaxLifeEvents
	}
	// zero is a legitimate "no cool-down", but it is also what an unset param reads as; treat it
	// as unset, because a chain that wants no cool-down can express that by allowing the update
	// policy to reject nothing else
	if limits.MinBlocksBetweenUpdates == 0 {
		limits.MinBlocksBetweenUpdates = DefaultUpdateCredentialMinBlocksBetweenUpdates
	}
	return limits
}

// UpdateCredentialFeeFromParams falls back to the compiled-in default so a chain that predates
// the param does not get a free update.
func UpdateCredentialFeeFromParams(p types.Params) string {
	if p.UpdateCredentialFee == "" {
		return DefaultUpdateCredentialFee
	}
	return p.UpdateCredentialFee
}

// ErrUpdateRejected wraps every policy rejection.  Callers map it to
// types.ErrCredentialUpdateRejected; the wrapped text is for the log, not for the user.
var ErrUpdateRejected = errors.New("credential update rejected by change policy")

// ErrUpdateRateLimited wraps every rate-limit refusal.  Kept distinct from ErrUpdateRejected
// because the two mean different things to a user: one says "this change is not allowed", the
// other says "not yet" or "not again".
var ErrUpdateRateLimited = errors.New("credential update rate limited")

func rejectf(format string, args ...interface{}) error {
	return fmt.Errorf("%w: %s", ErrUpdateRejected, fmt.Sprintf(format, args...))
}

func RateLimitf(format string, args ...interface{}) error {
	return fmt.Errorf("%w: %s", ErrUpdateRateLimited, fmt.Sprintf(format, args...))
}

// ClassifyPersonalInfoUpdate decides whether newDetails is a legitimate revision of oldDetails.
//
// The security core is a single compiled-in rule: **at most one hash-contributing field may
// change per update**.  Everything else only refines what that one field is allowed to do.  Two
// simultaneous changes are indistinguishable from substituting one person for another, so they
// are rejected regardless of how small each change is.  The one deliberate exception is the
// birthdate month/day swap, which is a single transposition even though it moves two components
// of one field.
//
// The caller is still responsible for the parts that are not a function of the plaintext diff:
// rate limits, alias-count caps, and the alias-aware uniqueness check that stops a user
// correcting *into* an identity that already exists.
func ClassifyPersonalInfoUpdate(oldDetails, newDetails *types.EncryptablePersonalInfoDetails, policy UpdatePolicy) (UpdateVerdict, error) {
	if oldDetails == nil || newDetails == nil {
		return UpdateVerdict{}, rejectf("personal info details are nil")
	}

	// the new details are about to be hashed, so they must satisfy the hash's invariants
	// (canonical birthdate, no "," or "|", known gender) before anything else is decided
	if err := ValidatePersonalInfoDetails(newDetails); err != nil {
		return UpdateVerdict{}, err
	}

	policy = policy.WithDefaults()

	// Exact comparison, because that is what CreateCredentialHash sees.  A change that only
	// normalization would hide -- "Asuncion" to "asuncion" -- really does produce a different
	// hash and must be classified, not waved through.
	var changed []string
	if oldDetails.FirstName != newDetails.FirstName {
		changed = append(changed, UpdateFieldFirstName)
	}
	if oldDetails.MiddleName != newDetails.MiddleName {
		changed = append(changed, UpdateFieldMiddleName)
	}
	if oldDetails.LastName != newDetails.LastName {
		changed = append(changed, UpdateFieldLastName)
	}
	if oldDetails.Birthdate != newDetails.Birthdate {
		changed = append(changed, UpdateFieldBirthdate)
	}
	if oldDetails.Gender != newDetails.Gender {
		changed = append(changed, UpdateFieldGender)
	}

	switch len(changed) {
	case 0:
		// Citizenship and/or Residency may still have moved.  They are outside the hash but
		// inside credentialPedersenCommit, so this is a real update -- just an unconstrained one.
		return UpdateVerdict{Kind: UpdateKindFreeFieldsOnly}, nil
	case 1:
		// handled below
	default:
		return UpdateVerdict{}, rejectf("at most one identity field may change per update, got %d (%s)",
			len(changed), strings.Join(changed, ", "))
	}

	field := changed[0]
	verdict := UpdateVerdict{Kind: UpdateKindCorrection, ChangedField: field, HashChanged: true}

	switch field {
	case UpdateFieldFirstName:
		if !isNameCorrection(oldDetails.FirstName, newDetails.FirstName, false, policy) {
			return UpdateVerdict{}, rejectf("first name %q to %q is not a correction", oldDetails.FirstName, newDetails.FirstName)
		}
	case UpdateFieldMiddleName:
		if !isNameCorrection(oldDetails.MiddleName, newDetails.MiddleName, true, policy) {
			return UpdateVerdict{}, rejectf("middle name %q to %q is not a correction", oldDetails.MiddleName, newDetails.MiddleName)
		}
	case UpdateFieldLastName:
		// A surname legitimately changes wholesale on marriage or divorce, and no distance
		// bound models that.  It is safe only because the one-field rule still holds: the given
		// names and the birthdate continue to pin the identity, and the corrected data can only
		// originate from an authenticated IdentityServiceProvider.
		if isNameCorrection(oldDetails.LastName, newDetails.LastName, false, policy) {
			break
		}
		if !policy.AllowLastNameLifeEvent {
			return UpdateVerdict{}, rejectf("last name %q to %q is not a correction and life events are disabled",
				oldDetails.LastName, newDetails.LastName)
		}
		if strings.TrimSpace(newDetails.LastName) == "" {
			return UpdateVerdict{}, rejectf("last name may not be cleared")
		}
		verdict.Kind = UpdateKindLifeEvent
	case UpdateFieldBirthdate:
		if err := checkBirthdateCorrection(oldDetails.Birthdate, newDetails.Birthdate, policy); err != nil {
			return UpdateVerdict{}, err
		}
	case UpdateFieldGender:
		// The value space is {m, f, n} and ValidatePersonalInfoDetails has already enforced it,
		// so gender cannot be used to substitute an identity; the one-field rule and the rate
		// limit are the only constraints that matter.
		if !policy.AllowGenderChange {
			return UpdateVerdict{}, rejectf("gender changes are disabled")
		}
	}

	return verdict, nil
}

// isNameCorrection reports whether new is close enough to old to be a transcription fix.
// allowEmptyFill is set only for the middle name, the one name that is legitimately absent.
func isNameCorrection(oldName, newName string, allowEmptyFill bool, policy UpdatePolicy) bool {
	// Compare on a normalized form so that case and spacing differences cost nothing.  The
	// stored values keep their original spelling; this affects only the distance measure.
	o := normalizeNameForCompare(oldName)
	n := normalizeNameForCompare(newName)

	if allowEmptyFill && (o == "" || n == "") {
		return true
	}
	// An absent given name is not a correction in either direction.
	if o == "" || n == "" {
		return false
	}

	oldRunes := []rune(o)
	newRunes := []rune(n)

	// Initial expansion or contraction: "a" <-> "asuncion".  This is the commonest real middle
	// name correction and edit distance can never model it -- the distance is the whole name.
	if len(oldRunes) == 1 && oldRunes[0] == newRunes[0] {
		return true
	}
	if len(newRunes) == 1 && newRunes[0] == oldRunes[0] {
		return true
	}

	dist := restrictedEditDistance(oldRunes, newRunes)
	if dist > policy.MaxEditDistance {
		return false
	}
	// Integer form of dist/runeLen <= pct/100.  Never float64 division: two enclaves must agree
	// bit for bit.
	runeLen := len(oldRunes)
	if len(newRunes) > runeLen {
		runeLen = len(newRunes)
	}
	return dist*100 <= policy.MaxEditDistancePercent*runeLen
}

// checkBirthdateCorrection accepts a birthdate change only if it looks like a single data-entry
// error.  Month-only and day-only changes are unbounded in magnitude on purpose: the one-field
// rule already caps the blast radius at the ~31 candidate identities that share everything else.
func checkBirthdateCorrection(oldBirthdate, newBirthdate string, policy UpdatePolicy) error {
	oldT, err := NormalizeBirthdateTime(oldBirthdate)
	if err != nil {
		return rejectf("stored birthdate %q is not formatted as %s", oldBirthdate, PersonalInfoBirthdateLayout)
	}
	// ValidatePersonalInfoDetails already checked the new one, so this cannot fail; parse it
	// here anyway rather than assuming an ordering between the two checks.
	newT, err := NormalizeBirthdateTime(newBirthdate)
	if err != nil {
		return rejectf("birthdate %q is not formatted as %s", newBirthdate, PersonalInfoBirthdateLayout)
	}

	oldY, oldM, oldD := oldT.Date()
	newY, newM, newD := newT.Date()

	// ISO-versus-US entry error: 1970-Feb-03 keyed as 1970-Mar-02.  Two components move, but it
	// is one transposition, so it is exempted from the single-component rule below.
	if newY == oldY && int(newM) == oldD && newD == int(oldM) {
		return nil
	}

	differing := 0
	if newY != oldY {
		differing++
	}
	if newM != oldM {
		differing++
	}
	if newD != oldD {
		differing++
	}
	if differing != 1 {
		return rejectf("birthdate %q to %q changes %d components", oldBirthdate, newBirthdate, differing)
	}

	if newY == oldY {
		// a month-only or day-only change
		return nil
	}

	// A year is four digits with no separators, so a mistyped or transposed digit is exactly a
	// restricted edit distance of 1 ("1970" <-> "1907" is one adjacent transposition).
	if restrictedEditDistance([]rune(fmt.Sprintf("%04d", oldY)), []rune(fmt.Sprintf("%04d", newY))) <= 1 {
		return nil
	}
	delta := newY - oldY
	if delta < 0 {
		delta = -delta
	}
	if delta <= policy.MaxYearDelta {
		return nil
	}
	return rejectf("birth year %d to %d is neither a digit error nor within %d years", oldY, newY, policy.MaxYearDelta)
}

// normalizeNameForCompare lowercases, trims, and collapses internal whitespace runs to a single
// space.  Stdlib only, by design (see the file comment).
func normalizeNameForCompare(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))

	var b strings.Builder
	b.Grow(len(s))
	inSpace := false
	for _, r := range s {
		if unicode.IsSpace(r) {
			inSpace = true
			continue
		}
		if inSpace {
			b.WriteRune(' ')
			inSpace = false
		}
		b.WriteRune(r)
	}
	return b.String()
}

// restrictedEditDistance is the optimal string alignment distance: Levenshtein plus adjacent
// transposition, with no substring edited more than once.  That restriction is what makes it
// cheap and, more importantly, exactly specifiable -- unrestricted Damerau-Levenshtein has
// several published variants and the enclave cannot afford ambiguity about which one it runs.
func restrictedEditDistance(a, b []rune) int {
	if len(a) == 0 {
		return len(b)
	}
	if len(b) == 0 {
		return len(a)
	}

	// three rolling rows: prev2 = i-2, prev = i-1, cur = i
	prev2 := make([]int, len(b)+1)
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)

	for j := 0; j <= len(b); j++ {
		prev[j] = j
	}

	for i := 1; i <= len(a); i++ {
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			min := prev[j] + 1 // deletion
			if ins := cur[j-1] + 1; ins < min {
				min = ins
			}
			if sub := prev[j-1] + cost; sub < min {
				min = sub
			}
			if i > 1 && j > 1 && a[i-1] == b[j-2] && a[i-2] == b[j-1] {
				if trans := prev2[j-2] + 1; trans < min {
					min = trans
				}
			}
			cur[j] = min
		}
		prev2, prev, cur = prev, cur, prev2
	}

	return prev[len(b)]
}
