package main

// THE PEER VOTE THAT PROMOTES AN ENCLAVE MEASUREMENT.
//
// Two defects, found 2026-08-21 while rolling unique049 onto the 4-validator fleet (backlog 92):
//
//   1. the vote reused getThreshold, a SHAMIR threshold, as its quorum.  getThreshold(3) is 1, so a
//      SINGLE peer's "yes" promoted a measurement -- and the curve FLATTENS as the fleet grows, so
//      trust got cheaper to forge the larger the network became.
//   2. condemnation required no majority of its own: anything short of promotion was `inactive`,
//      which is broadcast and PERMANENT.  On an even voter count a 2-2 split burned the measurement.
//
// These tests pin the replacement.  Every one of them fails against the previous rule -- verified by
// reverting getVoteThreshold to getThreshold and decideIdentity's condemn arm to
// `activeCount < threshold`, per the negative-control discipline in backlog item 80.

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestVoteThresholdIsStrictMajority covers both parities.  The even rows are the point: v/2+1 is
// strictly more than half, so a tie can never reach it.
func TestVoteThresholdIsStrictMajority(t *testing.T) {
	for _, tc := range []struct{ voters, want int }{
		{0, 1}, {1, 1}, {2, 2}, {3, 2}, {4, 3}, {5, 3}, {6, 4}, {7, 4}, {10, 6},
	} {
		require.Equal(t, tc.want, getVoteThreshold(tc.voters),
			"%d voters: a verdict must carry strictly more than half", tc.voters)
		if tc.voters > 0 {
			require.Greater(t, tc.want*2, tc.voters,
				"%d voters: threshold %d must exceed half, or a tie could win", tc.voters, tc.want)
		}
	}
}

// TestVoteThresholdIsNotTheShamirThreshold is the regression that matters most: these two must never
// be the same function again.  The 3-voter row is the live fleet, where the old rule let one peer decide.
func TestVoteThresholdIsNotTheShamirThreshold(t *testing.T) {
	require.Equal(t, 1, getThreshold(3), "precondition: the Shamir curve really does return 1 here")
	require.Equal(t, 2, getVoteThreshold(3),
		"on the 4-validator fleet (3 peers) a single compromised peer must not be able to promote")

	// The Shamir curve flattens; a security threshold must not.
	require.Equal(t, 3, getThreshold(7))
	require.Equal(t, 4, getVoteThreshold(7))
	for v := 2; v <= 20; v++ {
		require.GreaterOrEqual(t, getVoteThreshold(v), getThreshold(v),
			"%d voters: the vote must never be cheaper than the Shamir threshold it replaced", v)
	}
}

func TestDecideIdentityRequiresAMajorityEitherWay(t *testing.T) {
	cases := []struct {
		name                              string
		pioneers, active, answered, thres int
		want                              identityVerdict
	}{
		// The even-voter tie -- 4 peers, 2 for and 2 against.  The old rule CONDEMNED here,
		// permanently, on a split vote.
		{"4 peers, 2-2 tie", 4, 2, 4, 3, verdictAbstain},
		{"4 peers, 3-1 for", 4, 3, 4, 3, verdictPromote},
		{"4 peers, 1-3 against", 4, 1, 4, 3, verdictCondemn},

		// The live fleet: 3 peers, threshold 2.  One "yes" used to be enough.
		// A lone "yes" with the others silent must NOT promote -- one peer is not a majority.
		{"3 peers, lone yes, others silent", 3, 1, 1, 2, verdictAbstain},
		// But 1 for / 2 against IS a real majority against, and condemning is correct.
		{"3 peers, 1 for 2 against", 3, 1, 3, 2, verdictCondemn},
		{"3 peers, two yes promotes", 3, 2, 3, 2, verdictPromote},
		{"3 peers, all refuse", 3, 0, 3, 2, verdictCondemn},

		// Too few answers to conclude anything -- unreachable peers must not become a verdict.
		{"3 peers, only one answered", 3, 0, 1, 2, verdictAbstain},
		{"3 peers, none answered", 3, 0, 0, 2, verdictAbstain},

		// The launch node: nobody to ask, so it decides on its own authority.
		{"no pioneers self-promotes", 0, 0, 0, 1, verdictPromote},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want,
				decideIdentity(tc.pioneers, tc.active, tc.answered, tc.thres),
				"got %s, want %s", decideIdentity(tc.pioneers, tc.active, tc.answered, tc.thres), tc.want)
		})
	}
}

// TestDecideIdentityNeverCondemnsWithoutRefusals is the safety property in general form: a
// measurement can only be permanently burned by peers that actually said no.  Swept across every
// voter count and split, so it cannot be satisfied by the table above alone.
func TestDecideIdentityNeverCondemnsWithoutRefusals(t *testing.T) {
	for pioneers := 1; pioneers <= 12; pioneers++ {
		thres := getVoteThreshold(pioneers)
		for answered := 0; answered <= pioneers; answered++ {
			for active := 0; active <= answered; active++ {
				v := decideIdentity(pioneers, active, answered, thres)
				refused := answered - active
				if v == verdictCondemn {
					require.GreaterOrEqual(t, refused, thres,
						"pioneers=%d answered=%d active=%d: condemned without a majority refusing",
						pioneers, answered, active)
				}
				if v == verdictPromote {
					require.GreaterOrEqual(t, active, thres,
						"pioneers=%d answered=%d active=%d: promoted without a majority in favour",
						pioneers, answered, active)
				}
				// Promote and condemn can never both be reachable: that would mean two
				// majorities among `answered` voters.
				require.LessOrEqual(t, min(active, refused), thres-1,
					"pioneers=%d answered=%d active=%d: two majorities is arithmetically impossible",
					pioneers, answered, active)
			}
		}
	}
}
