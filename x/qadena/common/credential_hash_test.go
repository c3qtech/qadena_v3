package common

import (
	"strings"
	"testing"

	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

// The identity hash is the key of the enclave's uniqueness index, and that index is an EXACT
// lookup.  So every pair of spellings that a human would call the same name must hash the same, and
// every pair that names two different people must not.  Those are the two halves of this file, and
// the second matters more: a missed collision leaves the status quo, whereas a false collision
// permanently locks the second person out of claiming their own identity.

// The two spellings of the same surname: one carries U+0303 COMBINING TILDE after a plain "n", the
// other a single precomposed U+00F1.  They are visually identical, so nothing on screen tells them
// apart -- and editors, formatters and file-writing tools normalize Unicode silently, which can turn
// the decomposed form into the precomposed one and leave a test that passes while checking nothing.
// TestValidateRejectsDecomposedNames asserts they are still byte-different before relying on them;
// if that guard ever fires, these constants have been normalized and must be restored (hexdump
// should show "6e cc 83" here and "c3 b1" below).
const (
	decomposedPena  = "Peña" // "n" followed by a combining tilde
	precomposedPena = "Peña"  // a single "ñ" rune
)

// withField copies details and applies one mutation, so a case can vary a single field without
// disturbing the others.
func withField(pd *types.EncryptablePersonalInfoDetails, mutate func(*types.EncryptablePersonalInfoDetails)) *types.EncryptablePersonalInfoDetails {
	cp := *pd
	mutate(&cp)
	return &cp
}

func detailsWithName(first, middle, last string) *types.EncryptablePersonalInfoDetails {
	return &types.EncryptablePersonalInfoDetails{
		FirstName:  first,
		MiddleName: middle,
		LastName:   last,
		Birthdate:  "1980-Jun-15",
		Gender:     "f",
	}
}

// Spellings that must collapse to one identity.  Each of these was a distinct identity before
// CreateCredentialHash canonicalized its name inputs, which meant the anti-squatting check could be
// walked past with the shift key.
func TestCredentialHashIgnoresCaseAndSpacing(t *testing.T) {
	want := CreateCredentialHash(detailsWithName("maria", "asuncion", "dela cruz"))

	same := []struct {
		name                string
		first, middle, last string
	}{
		{"upper case", "MARIA", "ASUNCION", "DELA CRUZ"},
		{"title case", "Maria", "Asuncion", "Dela Cruz"},
		{"mixed case", "mArIa", "aSuNcIoN", "dEla cRuz"},
		{"leading and trailing spaces", "  maria ", " asuncion", "dela cruz  "},
		{"doubled internal space", "maria", "asuncion", "dela  cruz"},
		{"tab as separator", "maria", "asuncion", "dela\tcruz"},
		{"non breaking space", "maria", "asuncion", "dela cruz"},
		{"everything at once", "  MARIA\t", " Asuncion ", "DELA   Cruz "},
	}

	for _, tc := range same {
		t.Run(tc.name, func(t *testing.T) {
			got := CreateCredentialHash(detailsWithName(tc.first, tc.middle, tc.last))
			if got != want {
				t.Errorf("%q/%q/%q hashed to a different identity than the canonical spelling",
					tc.first, tc.middle, tc.last)
			}
		})
	}
}

// The other direction.  Diacritics and punctuation are NOT folded away: these are different people,
// and merging them would deny the second one their identity.
func TestCredentialHashKeepsDistinctNamesDistinct(t *testing.T) {
	distinct := []struct {
		name                string
		first, middle, last string
	}{
		{"pena", "jose", "", "Pena"},
		{"pena with tilde", "jose", "", "Peña"},
		{"muller without umlaut", "hans", "", "Muller"},
		{"muller with umlaut", "hans", "", "Müller"},
		{"obrien with apostrophe", "sean", "", "O'Brien"},
		{"obrien without apostrophe", "sean", "", "OBrien"},
		{"hyphenated", "ana", "", "Reyes-Santos"},
		{"spaced instead of hyphenated", "ana", "", "Reyes Santos"},
		{"middle name absent", "ana", "", "Reyes"},
		{"middle name present", "ana", "Lucia", "Reyes"},
	}

	seen := map[string]string{}
	for _, tc := range distinct {
		h := CreateCredentialHash(detailsWithName(tc.first, tc.middle, tc.last))
		if prev, dup := seen[h]; dup {
			t.Errorf("%s collided with %s -- these are different people and must not share an identity",
				tc.name, prev)
		}
		seen[h] = tc.name
	}
}

// Field boundaries must stay unambiguous after canonicalization.  ValidatePersonalInfoDetails
// rejects "," and "|" so the joined form cannot be re-split differently, and canonicalization must
// not have introduced a new way to smuggle a boundary -- collapsing whitespace cannot, because a
// space is not a separator.
func TestCredentialHashFieldsDoNotBleed(t *testing.T) {
	a := CreateCredentialHash(detailsWithName("ana maria", "", "reyes"))
	b := CreateCredentialHash(detailsWithName("ana", "maria", "reyes"))
	if a == b {
		t.Error("a space inside the first name is being read as a field boundary")
	}
}

// Decomposed input is refused rather than normalized: golang.org/x/text is barred inside the
// enclave (module-versioned Unicode tables, a consensus hazard), so NFC is enforced by rejection
// using only the stdlib's combining-mark table.
func TestValidateRejectsDecomposedNames(t *testing.T) {
	decomposed := decomposedPena
	precomposed := precomposedPena

	if decomposed == precomposed {
		t.Fatal("test is not exercising what it claims: the two spellings are byte-identical")
	}

	if err := ValidatePersonalInfoDetails(detailsWithName("jose", "", decomposed)); err == nil {
		t.Error("decomposed last name was accepted; it would hash differently from the precomposed spelling")
	} else if !strings.Contains(err.Error(), "precomposed") {
		t.Errorf("unhelpful error for decomposed name: %v", err)
	}

	if err := ValidatePersonalInfoDetails(detailsWithName("jose", "", precomposed)); err != nil {
		t.Errorf("precomposed last name was rejected: %v", err)
	}
}

// Each broken invariant must map to its own reason code, because the code is all the identity
// provider gets back -- the enclave cannot return the detailed message without publishing the
// decrypted field in a transaction error.
func TestPersonalInfoReasonOf(t *testing.T) {
	valid := detailsWithName("maria", "asuncion", "dela cruz")

	tests := []struct {
		name    string
		details *types.EncryptablePersonalInfoDetails
		want    PersonalInfoReason
	}{
		{"valid", valid, PersonalInfoOK},
		{"nil", nil, PersonalInfoNilDetails},
		{"comma in last name", detailsWithName("maria", "", "dela,cruz"), PersonalInfoSeparatorInField},
		{"pipe in first name", detailsWithName("mar|a", "", "cruz"), PersonalInfoSeparatorInField},
		{"decomposed last name", detailsWithName("jose", "", decomposedPena), PersonalInfoDecomposedName},
		{"unparseable birthdate", withField(valid, func(pd *types.EncryptablePersonalInfoDetails) {
			pd.Birthdate = "15/06/1980"
		}), PersonalInfoBirthdateFormat},
		{"non canonical birthdate", withField(valid, func(pd *types.EncryptablePersonalInfoDetails) {
			pd.Birthdate = "1980-jun-15"
		}), PersonalInfoBirthdateNotCanonical},
		{"bad gender", withField(valid, func(pd *types.EncryptablePersonalInfoDetails) {
			pd.Gender = "x"
		}), PersonalInfoInvalidGender},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := PersonalInfoReasonOf(tt.details); got != tt.want {
				t.Errorf("PersonalInfoReasonOf = %d, want %d", got, tt.want)
			}
			// the two forms must agree on whether the details are acceptable at all
			err := ValidatePersonalInfoDetails(tt.details)
			if (err == nil) != (tt.want == PersonalInfoOK) {
				t.Errorf("ValidatePersonalInfoDetails err=%v disagrees with reason %d", err, tt.want)
			}
		})
	}
}

// The reason messages cross the enclave boundary into a public transaction error, so none of them
// may quote what was submitted.  This test feeds in values distinctive enough to spot and fails if
// any of them reappears in the message -- so a future edit that helpfully interpolates the offending
// field is caught here rather than in a block explorer.
func TestPersonalInfoReasonMessagesLeakNothing(t *testing.T) {
	secrets := []string{"zzsecretfirst", "zzsecretmiddle", "zzsecretlast", "1999-Dec-31", "q"}

	details := &types.EncryptablePersonalInfoDetails{
		FirstName:  secrets[0],
		MiddleName: secrets[1],
		LastName:   secrets[2],
		Birthdate:  secrets[3],
		Gender:     secrets[4],
	}

	// this one is invalid (gender "q"), so a reason is produced
	reason := PersonalInfoReasonOf(details)
	if reason == PersonalInfoOK {
		t.Fatal("test details were supposed to be invalid")
	}

	for _, r := range []PersonalInfoReason{
		PersonalInfoOK, PersonalInfoNilDetails, PersonalInfoSeparatorInField,
		PersonalInfoDecomposedName, PersonalInfoBirthdateFormat,
		PersonalInfoBirthdateNotCanonical, PersonalInfoInvalidGender,
		PersonalInfoReason(999), // unknown codes must be safe too
	} {
		msg := r.Message()
		for _, s := range secrets {
			if s != "" && strings.Contains(msg, s) {
				t.Errorf("reason %d leaks a submitted value (%q) in %q", r, s, msg)
			}
		}
	}

	// and every known reason must actually say something
	for _, r := range []PersonalInfoReason{
		PersonalInfoNilDetails, PersonalInfoSeparatorInField, PersonalInfoDecomposedName,
		PersonalInfoBirthdateFormat, PersonalInfoBirthdateNotCanonical, PersonalInfoInvalidGender,
	} {
		if r.Message() == "" {
			t.Errorf("reason %d has no message", r)
		}
	}
}

// Canonicalization must not let a name validate its way past the emptiness rules by being all
// whitespace -- " " and "" are the same name, and the policy already refuses to clear a surname.
func TestCanonicalizeNameCollapsesWhitespaceOnlyToEmpty(t *testing.T) {
	for _, s := range []string{"", " ", "\t", "  \t \n "} {
		if got := CanonicalizeName(s); got != "" {
			t.Errorf("CanonicalizeName(%q) = %q, want empty", s, got)
		}
	}
}

// The policy engine and the hash must agree on what "the same name" means, or
// ClassifyPersonalInfoUpdate reports HashChanged for a hash that did not move and
// enclave_update_credential.go rejects the update as a fault.  normalizeNameForCompare delegating
// to CanonicalizeName is what guarantees this; this test fails if they are ever forked apart.
func TestPolicyNormalizerMatchesHashCanonicalizer(t *testing.T) {
	for _, s := range []string{"Maria", "  DELA  CRUZ ", "Peña", "o'brien", "juan\tcarlos", ""} {
		if normalizeNameForCompare(s) != CanonicalizeName(s) {
			t.Errorf("normalizeNameForCompare and CanonicalizeName disagree on %q", s)
		}
	}
}
