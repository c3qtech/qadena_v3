package main

// Paging tests for the sync-enclave handshake.
//
// These deliberately drive the pager with a ONE BYTE budget so that every entry lands on its own
// page. In production the budget is 1 MiB against ~166 entries today (one entry per
// keyUpdateFrequency=555 blocks), so the real traffic is a single page and would stay that way for
// years -- the multi-page path would first execute on a chain old enough to need it, in front of a
// customer, having never run. Forcing the small budget here is the only way this code gets
// exercised before then.

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

// seedOwners writes n owner entries with deliberately NON-sequential insertion order, so a pager
// that accidentally depends on store iteration order rather than sorting will fail here.
func seedOwners(t *testing.T, s *qadenaServer, n int) map[string][]string {
	t.Helper()
	want := make(map[string][]string, n)
	m := &types.EncryptableEnclaveSSOwnerMap{Pioneers: make(map[string]*types.EncryptablePioneerIDs, n)}
	for i := 0; i < n; i++ {
		// Scatter the keys: i*7 mod n is a permutation whenever gcd(7,n)==1.
		key := fmt.Sprintf("pubkid-%03d", (i*7)%n)
		ids := []string{fmt.Sprintf("pioneer-%d", i%3), fmt.Sprintf("pioneer-%d", (i+1)%3)}
		m.Pioneers[key] = &types.EncryptablePioneerIDs{PioneerIDs: ids}
		want[key] = ids
	}
	s.setAllOwners(m, 0)
	return want
}

// drainPages walks the pager exactly the way the joining enclave does, and returns everything it
// collected plus the number of round trips.
func drainPages(t *testing.T, s *qadenaServer, budget int) (map[string][]string, int) {
	t.Helper()
	got := make(map[string][]string)
	cursor := ""
	pages := 0
	for {
		pages++
		require.Less(t, pages, 5000, "pager did not terminate -- cursor is not advancing")

		page, next, done := s.getOwnersPage(cursor, budget)
		for k, v := range page {
			_, dup := got[k]
			require.False(t, dup, "key %q returned on more than one page -- the cursor overlaps", k)
			got[k] = v.PioneerIDs
		}
		if done {
			return got, pages
		}
		require.NotEmpty(t, next, "page is not done but returned no cursor; the joiner would spin")
		require.Greater(t, next, cursor, "cursor must advance strictly, got %q after %q", next, cursor)
		cursor = next
	}
}

// The one that matters: a budget so small every entry needs its own page.
func TestGetOwnersPage_TinyBudgetPagesEverything(t *testing.T) {
	s := newTestEnclaveServer(t)
	const n = 50
	want := seedOwners(t, s, n)

	got, pages := drainPages(t, s, 1)

	require.Equal(t, want, got, "paged reassembly must equal what was stored")
	require.Greater(t, pages, 1, "a 1-byte budget must produce many pages, otherwise this test is "+
		"not exercising the paging path at all")
	require.LessOrEqual(t, pages, n+1, "should not need more pages than entries")
}

// Whatever the budget, the reassembled map must equal the unpaged answer. Paging is a transport
// detail; it must not change what the joiner ends up holding.
func TestGetOwnersPage_MatchesUnpagedAcrossBudgets(t *testing.T) {
	for _, budget := range []int{1, 2, 7, 64, 1024, syncEnclavePageTargetBytes} {
		t.Run(fmt.Sprintf("budget=%d", budget), func(t *testing.T) {
			s := newTestEnclaveServer(t)
			seedOwners(t, s, 37)

			unpaged := s.getAllOwners()
			got, _ := drainPages(t, s, budget)

			require.Len(t, got, len(unpaged.Pioneers))
			for k, v := range unpaged.Pioneers {
				require.Equal(t, v.PioneerIDs, got[k], "entry %q differs from the unpaged answer", k)
			}
		})
	}
}

// Sorted order is what makes the cursor a stable position. store.Keys() promises no ordering, so
// without the sort a second call could skip or repeat entries -- and a skipped SS interval does not
// fail here, it becomes a getSSPrivK returning "" much later.
func TestGetOwnersPage_KeysComeBackSorted(t *testing.T) {
	s := newTestEnclaveServer(t)
	seedOwners(t, s, 20)

	var seen []string
	cursor := ""
	for {
		page, next, done := s.getOwnersPage(cursor, 1)
		for k := range page {
			seen = append(seen, k)
		}
		if done {
			break
		}
		cursor = next
	}

	require.Len(t, seen, 20)
	for i := 1; i < len(seen); i++ {
		require.Less(t, seen[i-1], seen[i], "pages must arrive in ascending key order")
	}
}

// A large budget must settle it in a single round trip -- the common case, and the one that must
// not regress into needless chattiness.
func TestGetOwnersPage_SinglePageWhenBudgetIsAmple(t *testing.T) {
	s := newTestEnclaveServer(t)
	seedOwners(t, s, 166) // roughly today's chain: 92k blocks / 555

	page, _, done := s.getOwnersPage("", syncEnclavePageTargetBytes)

	require.True(t, done, "166 entries must fit in one 1 MiB page")
	require.Len(t, page, 166)
}

// An enclave with no owners yet must finish immediately rather than report "not done" with nothing
// to send, which would spin the joiner.
func TestGetOwnersPage_EmptyStoreIsDone(t *testing.T) {
	s := newTestEnclaveServer(t)

	page, next, done := s.getOwnersPage("", syncEnclavePageTargetBytes)

	require.True(t, done)
	require.Empty(t, page)
	require.Empty(t, next)
}

// A cursor past the last key is the natural end state; it must terminate, not wrap.
func TestGetOwnersPage_CursorPastEndIsDone(t *testing.T) {
	s := newTestEnclaveServer(t)
	seedOwners(t, s, 10)

	page, _, done := s.getOwnersPage("zzz-past-everything", syncEnclavePageTargetBytes)

	require.True(t, done)
	require.Empty(t, page)
}
