package keeper

import "testing"

// The classification is deliberately testable on its own: every other part of reconcileEnclaveHeight
// needs a header service, a gRPC client and a live enclave, and none of those bear on the decision.
//
// The case that matters most here is the pair at the top.  A node joining by BLOCK-SYNC and a node
// restored by STATE-SYNC both present prepared == 0, and nothing else about them differs at this
// point -- same empty enclave, same intent to join.  The ONLY discriminator is whether the chain has
// already committed history, and getting it wrong is expensive in both directions: halt the
// block-sync joiner and no node can ever join; wave the state-synced one through and it executes
// blocks against an empty AML window and forks.
func TestClassifyEnclaveHeight(t *testing.T) {
	for _, tc := range []struct {
		name                             string
		prepared, confirmed, chainHeight int64
		want                             heightVerdict
	}{
		// -- the fresh/stranded split --
		{"genesis", 0, 0, 0, verdictFresh},
		{"block-sync joiner at first block", 0, 0, 0, verdictFresh},
		{"state-synced joiner", 0, 0, 60000, verdictHaltNoHistory},
		{"wiped enclave, chain kept", 0, 0, 1, verdictHaltNoHistory},

		// -- the ordinary running cases --
		{"healthy", 500, 500, 500, verdictHealthy},
		{"crashed in the confirm window", 500, 499, 500, verdictConfirmOnly},
		{"never confirmed anything", 500, 0, 500, verdictConfirmOnly},

		// -- enclave ahead: prepared but the chain never committed --
		{"one block ahead", 501, 500, 500, verdictRollback},
		{"far ahead after a chain-only rollback", 900, 900, 500, verdictRollback},

		// -- enclave behind: the blocks will never replay --
		{"one block behind", 499, 499, 500, verdictHaltBehind},
		{"far behind", 1, 1, 60000, verdictHaltBehind},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyEnclaveHeight(tc.prepared, tc.confirmed, tc.chainHeight); got != tc.want {
				t.Fatalf("classifyEnclaveHeight(prepared=%d, confirmed=%d, chain=%d) = %d, want %d",
					tc.prepared, tc.confirmed, tc.chainHeight, got, tc.want)
			}
		})
	}
}

// A fresh enclave must be waved through at chain height 0 and refused at every height above it.
// Written as a sweep rather than a couple of points because the boundary is the whole property:
// an off-by-one here either bricks joining entirely or restores the silent fork.
func TestFreshEnclaveIsOnlyAcceptableOnAnEmptyChain(t *testing.T) {
	if got := classifyEnclaveHeight(0, 0, 0); got != verdictFresh {
		t.Fatalf("a fresh enclave on an empty chain must be allowed to seed, got %d", got)
	}
	for _, chainHeight := range []int64{1, 2, 1500, 60000, 1 << 40} {
		if got := classifyEnclaveHeight(0, 0, chainHeight); got != verdictHaltNoHistory {
			t.Fatalf("a fresh enclave at chain height %d must halt, got %d", chainHeight, got)
		}
	}
}
