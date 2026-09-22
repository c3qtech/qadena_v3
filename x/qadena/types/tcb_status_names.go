package types

import (
	"sort"

	"github.com/edgelesssys/ego/attestation/tcbstatus"
)

// THE NAME <-> STATUS TABLE LIVES IN types, NOT common, FOR ONE REASON: Params.Validate needs it.
//
// common imports types, so types cannot import common.  The set arithmetic that actually decides
// what a node trusts is in x/qadena/common/tcbpolicy.go, next to the compiled allow-set it
// intersects with; only the naming is here.  That is the same split the assertion-mode constants
// take (params_validate.go), and for the same reason: Validate is the one place that must reject a
// value the rest of the system will never see.
//
// NAMES, NOT NUMBERS, IN THE PARAM.  tcbstatus.Status is an iota, so its numbers are an ego
// implementation detail -- OutOfDate is 1 and OutOfDateConfigurationNeeded is 4, an adjacency that
// has already produced one real bug in this repo (a deny-list compared against 1 and silently
// admitted 4).  A governance proposal that says "SWHardeningNeeded" is reviewable by a human; one
// that says "5" is not, and would silently change meaning if ego ever renumbered.
var tcbStatusByName = map[string]tcbstatus.Status{
	"UpToDate":                          tcbstatus.UpToDate,
	"OutOfDate":                         tcbstatus.OutOfDate,
	"Revoked":                           tcbstatus.Revoked,
	"ConfigurationNeeded":               tcbstatus.ConfigurationNeeded,
	"OutOfDateConfigurationNeeded":      tcbstatus.OutOfDateConfigurationNeeded,
	"SWHardeningNeeded":                 tcbstatus.SWHardeningNeeded,
	"ConfigurationAndSWHardeningNeeded": tcbstatus.ConfigurationAndSWHardeningNeeded,
}

// ParseTCBStatusName resolves a canonical status name.  Exact match only -- no case folding and no
// trimming, because a param that quietly accepted "uptodate  " would make two proposals that look
// different mean the same thing, and the reverse mistake (a name that looks right and matches
// nothing) is exactly what Validate exists to catch.
func ParseTCBStatusName(name string) (tcbstatus.Status, bool) {
	s, ok := tcbStatusByName[name]
	return s, ok
}

// TCBStatusNames lists every accepted name, sorted, for error messages.
func TCBStatusNames() []string {
	names := make([]string, 0, len(tcbStatusByName))
	for n := range tcbStatusByName {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
