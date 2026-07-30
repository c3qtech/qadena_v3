package common

import (
	"errors"
	"testing"

	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

// baseDetails is the seeded identity the test scripts use for "al".
func baseDetails() *types.EncryptablePersonalInfoDetails {
	return &types.EncryptablePersonalInfoDetails{
		FirstName:   "alberto",
		MiddleName:  "asuncion",
		LastName:    "villarica",
		Birthdate:   "1970-Feb-02",
		Citizenship: "PH",
		Residency:   "PH",
		Gender:      types.GenderM,
	}
}

// mutate returns a copy of baseDetails with the named fields replaced.
func mutate(f func(pd *types.EncryptablePersonalInfoDetails)) *types.EncryptablePersonalInfoDetails {
	pd := baseDetails()
	f(pd)
	return pd
}

func TestClassifyPersonalInfoUpdate(t *testing.T) {
	policy := DefaultUpdatePolicy()

	tests := []struct {
		name         string
		policy       *UpdatePolicy // nil means DefaultUpdatePolicy
		old          *types.EncryptablePersonalInfoDetails
		new          *types.EncryptablePersonalInfoDetails
		wantErr      bool
		wantKind     UpdateKind
		wantField    string
		wantHashMove bool
	}{
		// ---- nothing hash-contributing changed ----
		{
			name:     "identical details",
			old:      baseDetails(),
			new:      baseDetails(),
			wantKind: UpdateKindFreeFieldsOnly,
		},
		{
			name:     "citizenship only",
			old:      baseDetails(),
			new:      mutate(func(pd *types.EncryptablePersonalInfoDetails) { pd.Citizenship = "US" }),
			wantKind: UpdateKindFreeFieldsOnly,
		},
		{
			name: "citizenship and residency together",
			old:  baseDetails(),
			new: mutate(func(pd *types.EncryptablePersonalInfoDetails) {
				pd.Citizenship = "US"
				pd.Residency = "SG"
			}),
			wantKind: UpdateKindFreeFieldsOnly,
		},

		// ---- given-name corrections ----
		{
			name:         "middle name transposition asunicon to asuncion",
			old:          mutate(func(pd *types.EncryptablePersonalInfoDetails) { pd.MiddleName = "asunicon" }),
			new:          baseDetails(),
			wantKind:     UpdateKindCorrection,
			wantField:    UpdateFieldMiddleName,
			wantHashMove: true,
		},
		{
			name:         "first name one substitution",
			old:          baseDetails(),
			new:          mutate(func(pd *types.EncryptablePersonalInfoDetails) { pd.FirstName = "alberta" }),
			wantKind:     UpdateKindCorrection,
			wantField:    UpdateFieldFirstName,
			wantHashMove: true,
		},
		{
			name:         "first name case only",
			old:          baseDetails(),
			new:          mutate(func(pd *types.EncryptablePersonalInfoDetails) { pd.FirstName = "Alberto" }),
			wantKind:     UpdateKindCorrection,
			wantField:    UpdateFieldFirstName,
			wantHashMove: true,
		},
		{
			name:         "first name whitespace only",
			old:          baseDetails(),
			new:          mutate(func(pd *types.EncryptablePersonalInfoDetails) { pd.FirstName = " alberto " }),
			wantKind:     UpdateKindCorrection,
			wantField:    UpdateFieldFirstName,
			wantHashMove: true,
		},
		{
			name:         "first name collapsed internal whitespace",
			old:          mutate(func(pd *types.EncryptablePersonalInfoDetails) { pd.FirstName = "juan  carlos" }),
			new:          mutate(func(pd *types.EncryptablePersonalInfoDetails) { pd.FirstName = "juan carlos" }),
			wantKind:     UpdateKindCorrection,
			wantField:    UpdateFieldFirstName,
			wantHashMove: true,
		},
		{
			name:         "first name two edits within percent bound",
			old:          baseDetails(),
			new:          mutate(func(pd *types.EncryptablePersonalInfoDetails) { pd.FirstName = "albertos" }),
			wantKind:     UpdateKindCorrection,
			wantField:    UpdateFieldFirstName,
			wantHashMove: true,
		},
		{
			name:    "first name three edits exceeds max distance",
			old:     baseDetails(),
			new:     mutate(func(pd *types.EncryptablePersonalInfoDetails) { pd.FirstName = "albertoxyz" }),
			wantErr: true,
		},
		{
			name:    "first name replaced wholesale",
			old:     baseDetails(),
			new:     mutate(func(pd *types.EncryptablePersonalInfoDetails) { pd.FirstName = "ferdinand" }),
			wantErr: true,
		},
		{
			name:    "short first name one edit fails percent bound",
			old:     mutate(func(pd *types.EncryptablePersonalInfoDetails) { pd.FirstName = "al" }),
			new:     mutate(func(pd *types.EncryptablePersonalInfoDetails) { pd.FirstName = "ax" }),
			wantErr: true,
		},
		{
			name:    "first name cleared",
			old:     baseDetails(),
			new:     mutate(func(pd *types.EncryptablePersonalInfoDetails) { pd.FirstName = "" }),
			wantErr: true,
		},

		// ---- initial expansion / contraction / empty fill ----
		{
			name:         "middle initial expanded",
			old:          mutate(func(pd *types.EncryptablePersonalInfoDetails) { pd.MiddleName = "a" }),
			new:          baseDetails(),
			wantKind:     UpdateKindCorrection,
			wantField:    UpdateFieldMiddleName,
			wantHashMove: true,
		},
		{
			name:         "middle name contracted to initial",
			old:          baseDetails(),
			new:          mutate(func(pd *types.EncryptablePersonalInfoDetails) { pd.MiddleName = "a" }),
			wantKind:     UpdateKindCorrection,
			wantField:    UpdateFieldMiddleName,
			wantHashMove: true,
		},
		{
			name:    "middle initial expanded to a different name",
			old:     mutate(func(pd *types.EncryptablePersonalInfoDetails) { pd.MiddleName = "b" }),
			new:     baseDetails(),
			wantErr: true,
		},
		{
			name:         "middle name filled from empty",
			old:          mutate(func(pd *types.EncryptablePersonalInfoDetails) { pd.MiddleName = "" }),
			new:          baseDetails(),
			wantKind:     UpdateKindCorrection,
			wantField:    UpdateFieldMiddleName,
			wantHashMove: true,
		},
		{
			name:         "middle name cleared",
			old:          baseDetails(),
			new:          mutate(func(pd *types.EncryptablePersonalInfoDetails) { pd.MiddleName = "" }),
			wantKind:     UpdateKindCorrection,
			wantField:    UpdateFieldMiddleName,
			wantHashMove: true,
		},
		{
			name:    "first initial expansion is still a correction only by prefix",
			old:     mutate(func(pd *types.EncryptablePersonalInfoDetails) { pd.FirstName = "z" }),
			new:     baseDetails(),
			wantErr: true,
		},

		// ---- surname ----
		{
			name:         "last name correction quimba to quimbo",
			old:          mutate(func(pd *types.EncryptablePersonalInfoDetails) { pd.LastName = "quimba" }),
			new:          mutate(func(pd *types.EncryptablePersonalInfoDetails) { pd.LastName = "quimbo" }),
			wantKind:     UpdateKindCorrection,
			wantField:    UpdateFieldLastName,
			wantHashMove: true,
		},
		{
			name:         "last name life event quimba to villarica",
			old:          mutate(func(pd *types.EncryptablePersonalInfoDetails) { pd.LastName = "quimba" }),
			new:          baseDetails(),
			wantKind:     UpdateKindLifeEvent,
			wantField:    UpdateFieldLastName,
			wantHashMove: true,
		},
		{
			name:    "last name life event disabled by policy",
			policy:  &UpdatePolicy{MaxEditDistance: 2, MaxEditDistancePercent: 34, MaxYearDelta: 1, AllowGenderChange: true},
			old:     mutate(func(pd *types.EncryptablePersonalInfoDetails) { pd.LastName = "quimba" }),
			new:     baseDetails(),
			wantErr: true,
		},
		{
			name:    "last name cleared",
			old:     baseDetails(),
			new:     mutate(func(pd *types.EncryptablePersonalInfoDetails) { pd.LastName = "" }),
			wantErr: true,
		},

		// ---- birthdate ----
		{
			name:         "birthdate day off by one",
			old:          baseDetails(),
			new:          mutate(func(pd *types.EncryptablePersonalInfoDetails) { pd.Birthdate = "1970-Feb-03" }),
			wantKind:     UpdateKindCorrection,
			wantField:    UpdateFieldBirthdate,
			wantHashMove: true,
		},
		{
			name:         "birthdate month changed",
			old:          baseDetails(),
			new:          mutate(func(pd *types.EncryptablePersonalInfoDetails) { pd.Birthdate = "1970-Nov-02" }),
			wantKind:     UpdateKindCorrection,
			wantField:    UpdateFieldBirthdate,
			wantHashMove: true,
		},
		{
			name:         "birthdate month day swap",
			old:          mutate(func(pd *types.EncryptablePersonalInfoDetails) { pd.Birthdate = "1970-Feb-03" }),
			new:          mutate(func(pd *types.EncryptablePersonalInfoDetails) { pd.Birthdate = "1970-Mar-02" }),
			wantKind:     UpdateKindCorrection,
			wantField:    UpdateFieldBirthdate,
			wantHashMove: true,
		},
		{
			name:         "birth year digit transposition 1970 to 1907",
			old:          baseDetails(),
			new:          mutate(func(pd *types.EncryptablePersonalInfoDetails) { pd.Birthdate = "1907-Feb-02" }),
			wantKind:     UpdateKindCorrection,
			wantField:    UpdateFieldBirthdate,
			wantHashMove: true,
		},
		{
			name:         "birth year single digit typo 1970 to 1979",
			old:          baseDetails(),
			new:          mutate(func(pd *types.EncryptablePersonalInfoDetails) { pd.Birthdate = "1979-Feb-02" }),
			wantKind:     UpdateKindCorrection,
			wantField:    UpdateFieldBirthdate,
			wantHashMove: true,
		},
		{
			name:         "birth year within max delta",
			old:          baseDetails(),
			new:          mutate(func(pd *types.EncryptablePersonalInfoDetails) { pd.Birthdate = "1971-Feb-02" }),
			wantKind:     UpdateKindCorrection,
			wantField:    UpdateFieldBirthdate,
			wantHashMove: true,
		},
		{
			name:    "birth year substitution 1970 to 1995",
			old:     baseDetails(),
			new:     mutate(func(pd *types.EncryptablePersonalInfoDetails) { pd.Birthdate = "1995-Feb-02" }),
			wantErr: true,
		},
		{
			name:    "birthdate year and day both change",
			old:     baseDetails(),
			new:     mutate(func(pd *types.EncryptablePersonalInfoDetails) { pd.Birthdate = "1971-Feb-03" }),
			wantErr: true,
		},
		{
			name:    "birthdate not canonical",
			old:     baseDetails(),
			new:     mutate(func(pd *types.EncryptablePersonalInfoDetails) { pd.Birthdate = "1970-feb-03" }),
			wantErr: true,
		},
		{
			name:    "birthdate unparseable",
			old:     baseDetails(),
			new:     mutate(func(pd *types.EncryptablePersonalInfoDetails) { pd.Birthdate = "1970-02-03" }),
			wantErr: true,
		},
		{
			name:    "stored birthdate unparseable",
			old:     mutate(func(pd *types.EncryptablePersonalInfoDetails) { pd.Birthdate = "02/02/1970" }),
			new:     baseDetails(),
			wantErr: true,
		},

		// ---- gender ----
		{
			name:         "gender m to f",
			old:          baseDetails(),
			new:          mutate(func(pd *types.EncryptablePersonalInfoDetails) { pd.Gender = types.GenderF }),
			wantKind:     UpdateKindCorrection,
			wantField:    UpdateFieldGender,
			wantHashMove: true,
		},
		{
			name:         "gender m to n",
			old:          baseDetails(),
			new:          mutate(func(pd *types.EncryptablePersonalInfoDetails) { pd.Gender = types.GenderN }),
			wantKind:     UpdateKindCorrection,
			wantField:    UpdateFieldGender,
			wantHashMove: true,
		},
		{
			name:    "gender change disabled by policy",
			policy:  &UpdatePolicy{MaxEditDistance: 2, MaxEditDistancePercent: 34, MaxYearDelta: 1, AllowLastNameLifeEvent: true},
			old:     baseDetails(),
			new:     mutate(func(pd *types.EncryptablePersonalInfoDetails) { pd.Gender = types.GenderF }),
			wantErr: true,
		},
		{
			name:    "unknown gender value",
			old:     baseDetails(),
			new:     mutate(func(pd *types.EncryptablePersonalInfoDetails) { pd.Gender = "x" }),
			wantErr: true,
		},

		// ---- the core rule: more than one identity field ----
		{
			name: "first and last name both change",
			old:  baseDetails(),
			new: mutate(func(pd *types.EncryptablePersonalInfoDetails) {
				pd.FirstName = "alberta"
				pd.LastName = "villarico"
			}),
			wantErr: true,
		},
		{
			name: "two tiny corrections are still two",
			old:  baseDetails(),
			new: mutate(func(pd *types.EncryptablePersonalInfoDetails) {
				pd.FirstName = "albert"
				pd.MiddleName = "asuncio"
			}),
			wantErr: true,
		},
		{
			name: "identity substitution",
			old:  baseDetails(),
			new: mutate(func(pd *types.EncryptablePersonalInfoDetails) {
				pd.FirstName = "ferdinand"
				pd.MiddleName = "romualdez"
				pd.LastName = "marcos"
				pd.Birthdate = "1957-Sep-13"
			}),
			wantErr: true,
		},
		{
			name: "one identity field plus free fields",
			old:  baseDetails(),
			new: mutate(func(pd *types.EncryptablePersonalInfoDetails) {
				pd.LastName = "villarico"
				pd.Citizenship = "US"
				pd.Residency = "US"
			}),
			wantKind:     UpdateKindCorrection,
			wantField:    UpdateFieldLastName,
			wantHashMove: true,
		},

		// ---- non-ASCII ----
		{
			name:         "n tilde counts as one rune",
			old:          mutate(func(pd *types.EncryptablePersonalInfoDetails) { pd.LastName = "muñoz" }),
			new:          mutate(func(pd *types.EncryptablePersonalInfoDetails) { pd.LastName = "munoz" }),
			wantKind:     UpdateKindCorrection,
			wantField:    UpdateFieldLastName,
			wantHashMove: true,
		},
		{
			name:         "accented given name corrected",
			old:          mutate(func(pd *types.EncryptablePersonalInfoDetails) { pd.FirstName = "jose maria" }),
			new:          mutate(func(pd *types.EncryptablePersonalInfoDetails) { pd.FirstName = "josé maria" }),
			wantKind:     UpdateKindCorrection,
			wantField:    UpdateFieldFirstName,
			wantHashMove: true,
		},
		{
			name:         "cjk name one character corrected",
			old:          mutate(func(pd *types.EncryptablePersonalInfoDetails) { pd.LastName = "田中一郎" }),
			new:          mutate(func(pd *types.EncryptablePersonalInfoDetails) { pd.LastName = "田中二郎" }),
			wantKind:     UpdateKindCorrection,
			wantField:    UpdateFieldLastName,
			wantHashMove: true,
		},
		{
			name:    "cjk name replaced wholesale is a life event not a correction",
			old:     mutate(func(pd *types.EncryptablePersonalInfoDetails) { pd.FirstName = "田中一郎" }),
			new:     mutate(func(pd *types.EncryptablePersonalInfoDetails) { pd.FirstName = "山本花子" }),
			wantErr: true,
		},

		// ---- hash-invariant violations ----
		{
			name:    "comma in new last name",
			old:     baseDetails(),
			new:     mutate(func(pd *types.EncryptablePersonalInfoDetails) { pd.LastName = "villarica,jr" }),
			wantErr: true,
		},
		{
			name:    "pipe in new middle name",
			old:     baseDetails(),
			new:     mutate(func(pd *types.EncryptablePersonalInfoDetails) { pd.MiddleName = "asuncion|" }),
			wantErr: true,
		},
		{
			name:    "nil new details",
			old:     baseDetails(),
			new:     nil,
			wantErr: true,
		},
		{
			name:    "nil old details",
			old:     nil,
			new:     baseDetails(),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := policy
			if tt.policy != nil {
				p = *tt.policy
			}

			verdict, err := ClassifyPersonalInfoUpdate(tt.old, tt.new, p)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected rejection, got verdict %+v", verdict)
				}
				return
			}
			if err != nil {
				t.Fatalf("expected acceptance, got %v", err)
			}
			if verdict.Kind != tt.wantKind {
				t.Errorf("kind = %v, want %v", verdict.Kind, tt.wantKind)
			}
			if verdict.ChangedField != tt.wantField {
				t.Errorf("changed field = %q, want %q", verdict.ChangedField, tt.wantField)
			}
			if verdict.HashChanged != tt.wantHashMove {
				t.Errorf("hash changed = %v, want %v", verdict.HashChanged, tt.wantHashMove)
			}
			// HashChanged must agree with the hash the enclave will actually compute.
			gotHashMove := CreateCredentialHash(tt.old) != CreateCredentialHash(tt.new)
			if gotHashMove != verdict.HashChanged {
				t.Errorf("HashChanged = %v but CreateCredentialHash moved = %v", verdict.HashChanged, gotHashMove)
			}
		})
	}
}

// A rejection must be recognisable as one so the enclave can map it to
// types.ErrCredentialUpdateRejected rather than to a generic failure.
func TestClassifyRejectionWrapsErrUpdateRejected(t *testing.T) {
	old := baseDetails()
	new := mutate(func(pd *types.EncryptablePersonalInfoDetails) {
		pd.FirstName = "ferdinand"
		pd.LastName = "marcos"
	})

	_, err := ClassifyPersonalInfoUpdate(old, new, DefaultUpdatePolicy())
	if !errors.Is(err, ErrUpdateRejected) {
		t.Fatalf("err = %v, want it to wrap ErrUpdateRejected", err)
	}
}

// A chain that predates the update params reads every numeric as 0.  Without the fallback the
// percent rule would be 0 and every correction would be rejected.
func TestUpdatePolicyWithDefaults(t *testing.T) {
	zero := UpdatePolicy{AllowLastNameLifeEvent: true, AllowGenderChange: true}
	got := zero.WithDefaults()

	if got.MaxEditDistance != DefaultUpdateNameMaxEditDistance ||
		got.MaxEditDistancePercent != DefaultUpdateNameMaxEditDistancePercent ||
		got.MaxYearDelta != DefaultUpdateBirthdateMaxYearDelta {
		t.Fatalf("zero policy did not pick up defaults: %+v", got)
	}

	explicit := UpdatePolicy{MaxEditDistance: 1, MaxEditDistancePercent: 50, MaxYearDelta: 3}
	if got := explicit.WithDefaults(); got.MaxEditDistance != 1 || got.MaxEditDistancePercent != 50 || got.MaxYearDelta != 3 {
		t.Fatalf("explicit policy was overwritten: %+v", got)
	}

	old := baseDetails()
	new := mutate(func(pd *types.EncryptablePersonalInfoDetails) { pd.MiddleName = "asunicon" })
	if _, err := ClassifyPersonalInfoUpdate(old, new, zero); err != nil {
		t.Fatalf("zero-valued policy rejected a one-edit correction: %v", err)
	}
}

func TestRestrictedEditDistance(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"", "", 0},
		{"", "abc", 3},
		{"abc", "", 3},
		{"abc", "abc", 0},
		{"asunicon", "asuncion", 1}, // adjacent transposition
		{"1970", "1907", 1},         // adjacent transposition, digits
		{"1970", "1979", 1},         // substitution
		{"1970", "1995", 2},
		{"villarica", "villarico", 1},
		{"muñoz", "munoz", 1}, // one rune, not two bytes
		{"田中一郎", "田中二郎", 1},
		{"alberto", "albertos", 1},
		{"alberto", "ferdinand", 9},
		{"ca", "abc", 3}, // OSA does not reuse an edited substring
	}

	for _, tt := range tests {
		if got := restrictedEditDistance([]rune(tt.a), []rune(tt.b)); got != tt.want {
			t.Errorf("restrictedEditDistance(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
		// the measure must be symmetric, or the verdict would depend on argument order
		if got := restrictedEditDistance([]rune(tt.b), []rune(tt.a)); got != tt.want {
			t.Errorf("restrictedEditDistance(%q, %q) = %d, want %d (asymmetric)", tt.b, tt.a, got, tt.want)
		}
	}
}

func TestNormalizeNameForCompare(t *testing.T) {
	tests := []struct{ in, want string }{
		{"", ""},
		{"  ", ""},
		{"Alberto", "alberto"},
		{"  Alberto  ", "alberto"},
		{"juan  carlos", "juan carlos"},
		{"juan\tcarlos", "juan carlos"},
		{"DE LA CRUZ", "de la cruz"},
	}

	for _, tt := range tests {
		if got := normalizeNameForCompare(tt.in); got != tt.want {
			t.Errorf("normalizeNameForCompare(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
