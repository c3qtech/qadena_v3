package main

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"cosmossdk.io/store/prefix"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"
	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

// scanAcc recomputes a prefix's accumulator from the data itself -- the value the maintained one
// must equal.
func scanAcc(s *qadenaServer, pfx string) c.StoreAccumulator {
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(pfx))
	acc, _ := c.AccumulatorFromPrefixStore(store)
	return acc
}

// A REAL SETTER, not a hand-written store.Set, because what these tests are really checking is that
// the hooks are wired into the write paths -- the accumulator arithmetic itself is covered by the
// unit tests in x/qadena/common.
func putWallet(s *qadenaServer, id string) {
	s.setWalletNoNotify(types.Wallet{WalletID: id})
}

func TestAccumulatorTracksTheSettersItIsWiredInto(t *testing.T) {
	s := newTestEnclaveServer(t)

	// Establish it first: a table with no accumulator is deliberately not maintained, because
	// seeding writes thousands of rows and a value covering only "rows seen since startup" would be
	// worse than none.
	s.ensureAccumulator(types.WalletKeyPrefix)

	for i := 0; i < 20; i++ {
		putWallet(s, fmt.Sprintf("wallet%d", i))
	}
	maintained, ok := s.loadAccumulator(types.WalletKeyPrefix)
	require.True(t, ok)
	require.Equal(t, scanAcc(s, types.WalletKeyPrefix), maintained,
		"the maintained accumulator drifted from the data after inserts")
}

// The overwrite case is the one most likely to be mis-wired: forgetting to subtract the old value
// leaves both contributions in the sum forever.
func TestAccumulatorHandlesOverwrite(t *testing.T) {
	s := newTestEnclaveServer(t)
	s.ensureAccumulator(types.WalletKeyPrefix)

	putWallet(s, "w1")
	putWallet(s, "w1") // same key, rewritten
	putWallet(s, "w1")

	maintained, _ := s.loadAccumulator(types.WalletKeyPrefix)
	require.Equal(t, scanAcc(s, types.WalletKeyPrefix), maintained,
		"an overwrite left a stale contribution in the sum")
}

func TestAccumulatorHandlesDelete(t *testing.T) {
	s := newTestEnclaveServer(t)
	s.ensureAccumulator(types.CredentialKeyPrefix)

	s.setCredentialNoNotify("cred1", "personal-info", types.Credential{CredentialID: "cred1", CredentialType: "personal-info"})
	s.setCredentialNoNotify("cred2", "personal-info", types.Credential{CredentialID: "cred2", CredentialType: "personal-info"})
	s.removeCredentialNoNotify("cred1", "personal-info")

	maintained, _ := s.loadAccumulator(types.CredentialKeyPrefix)
	require.Equal(t, scanAcc(s, types.CredentialKeyPrefix), maintained,
		"a delete did not remove its contribution")
}

// Rows can arrive WITHOUT passing through a setter -- a snapshot restore, a bulk seed.  That is the
// shape that left the iavl fast index empty and CredentialPCXY short, so the accumulator must
// notice rather than report a confident wrong answer.
func TestAccumulatorEstablishedByScanAfterRowsArriveOutOfBand(t *testing.T) {
	s := newTestEnclaveServer(t)

	// Straight into the store, bypassing every setter and hook.
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(types.WalletKeyPrefix))
	for i := 0; i < 10; i++ {
		store.Set([]byte(fmt.Sprintf("k%d", i)), []byte("v"))
	}

	_, ok := s.loadAccumulator(types.WalletKeyPrefix)
	require.False(t, ok, "nothing should be stored yet -- absent must not read as a valid zero")

	require.Equal(t, scanAcc(s, types.WalletKeyPrefix), s.ensureAccumulator(types.WalletKeyPrefix),
		"establishing by scan must reproduce the data exactly")
}

// An empty table accumulates to zero, and that is a REAL value -- distinguishable from "no
// accumulator". Conflating the two is what the iavl storage_version marker got wrong.
func TestEmptyTableAccumulatesToAStoredZero(t *testing.T) {
	s := newTestEnclaveServer(t)

	acc := s.ensureAccumulator(types.PioneerJarKeyPrefix)
	require.Equal(t, c.StoreAccumulator{}, acc)

	stored, ok := s.loadAccumulator(types.PioneerJarKeyPrefix)
	require.True(t, ok, "an empty table's zero must be STORED, not absent")
	require.Equal(t, c.StoreAccumulator{}, stored)
}

// The shadow must catch a write path that does not maintain the accumulator -- which is the entire
// reason the scan keeps running alongside it.
func TestShadowComparisonDetectsAnUnhookedWrite(t *testing.T) {
	s := newTestEnclaveServer(t)
	s.ensureAccumulator(types.WalletKeyPrefix)
	putWallet(s, "w1")

	// Simulate a write path nobody hooked: straight to the store, no accumulateWrite.
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(types.WalletKeyPrefix))
	store.Set([]byte("smuggled"), []byte("row"))

	maintained, _ := s.loadAccumulator(types.WalletKeyPrefix)
	require.NotEqual(t, scanAcc(s, types.WalletKeyPrefix), maintained,
		"an unhooked write should make the maintained value wrong -- that is the hazard being tested")

	// The next hooked write repairs it, because the comparison scheduled a rebuild.
	s.markAccumulatorForReseed(types.WalletKeyPrefix)
	putWallet(s, "w2")

	repaired, _ := s.loadAccumulator(types.WalletKeyPrefix)
	require.Equal(t, scanAcc(s, types.WalletKeyPrefix), repaired,
		"the scheduled rebuild did not repair the accumulator")
}

// THE GAP THIS CLOSES: establishment used to piggyback on the next ordinary write to a store, so a
// store nobody writes to never got an accumulator at all.  EnclaveIdentity, PioneerJar and
// JarRegulator can go an entire run without a single write, which meant the shadow covered exactly
// the stores that needed watching least.  One block is now enough, with no traffic whatsoever.
func TestEndBlockEstablishesEveryAccumulatorWithoutAnyWrites(t *testing.T) {
	s := newTestEnclaveServer(t)

	for _, pfx := range storeHashKeys {
		_, ok := s.loadAccumulator(pfx)
		require.False(t, ok, "nothing should be established before the first block: "+pfx)
	}

	endBlock(t, s, 5)

	for _, pfx := range storeHashKeys {
		acc, ok := s.loadAccumulator(pfx)
		require.True(t, ok, "store never written still has no accumulator after a block: "+pfx)
		require.Equal(t, scanAcc(s, pfx), acc, "established value does not match the data: "+pfx)
	}
}

// Rows that arrived WITHOUT passing through a setter -- a bulk seed, a snapshot restore -- must be
// counted by the establishing scan.  This is the shape that left the iavl fast index empty and
// CredentialPCXY 972 rows short, so the accumulator has to derive from the data, not from events.
func TestEndBlockEstablishmentCountsRowsThatBypassedTheSetters(t *testing.T) {
	s := newTestEnclaveServer(t)

	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(types.PioneerJarKeyPrefix))
	for i := 0; i < 7; i++ {
		store.Set([]byte(fmt.Sprintf("jar%d", i)), []byte("smuggled-in"))
	}

	endBlock(t, s, 5)

	acc, ok := s.loadAccumulator(types.PioneerJarKeyPrefix)
	require.True(t, ok)
	require.Equal(t, scanAcc(s, types.PioneerJarKeyPrefix), acc,
		"the establishing scan missed rows that bypassed the setters")
}

// A flagged accumulator must be repaired by the block too, not left waiting for a write to that
// store -- otherwise a detected mismatch on a quiet store would persist indefinitely.
func TestEndBlockRebuildsAFlaggedAccumulator(t *testing.T) {
	s := newTestEnclaveServer(t)
	endBlock(t, s, 5)

	// Corrupt it the way an unhooked write path would: change the data, leave the accumulator.
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(types.WalletKeyPrefix))
	store.Set([]byte("unhooked"), []byte("row"))
	require.NotEqual(t, scanAcc(s, types.WalletKeyPrefix), mustLoadAcc(t, s, types.WalletKeyPrefix))

	s.markAccumulatorForReseed(types.WalletKeyPrefix)
	endBlock(t, s, 6)

	require.Equal(t, scanAcc(s, types.WalletKeyPrefix), mustLoadAcc(t, s, types.WalletKeyPrefix),
		"the block did not rebuild a flagged accumulator")
}

func mustLoadAcc(t *testing.T, s *qadenaServer, pfx string) c.StoreAccumulator {
	t.Helper()
	acc, ok := s.loadAccumulator(pfx)
	require.True(t, ok)
	return acc
}

// Marking must report whether it CHANGED anything.  A quiet store stays marked indefinitely --
// only a write to it clears the flag -- so the comparison uses this to announce the condition once
// rather than on every GetStoreHash, which EnclaveEndBlock runs unguarded whenever it checks sync.
func TestMarkingForReseedReportsOnlyTheTransition(t *testing.T) {
	s := newTestEnclaveServer(t)

	require.True(t, s.markAccumulatorForReseed(types.PioneerJarKeyPrefix), "first mark should report the change")
	require.False(t, s.markAccumulatorForReseed(types.PioneerJarKeyPrefix), "re-marking an already-marked store would log on every comparison")
	require.False(t, s.markAccumulatorForReseed(types.PioneerJarKeyPrefix))

	// Once drained, the condition can be announced again -- it is genuinely new at that point.
	require.True(t, s.takeAccumulatorReseed(types.PioneerJarKeyPrefix))
	require.True(t, s.markAccumulatorForReseed(types.PioneerJarKeyPrefix))
}

// The reseed flag must be one-shot: draining it twice would rebuild on every subsequent write,
// silently turning an O(1) update back into a full scan per write.
func TestReseedFlagIsOneShot(t *testing.T) {
	s := newTestEnclaveServer(t)
	s.markAccumulatorForReseed(types.WalletKeyPrefix)
	require.True(t, s.takeAccumulatorReseed(types.WalletKeyPrefix))
	require.False(t, s.takeAccumulatorReseed(types.WalletKeyPrefix), "flag was not cleared")
}

// The seam RPC's contract, both halves:
//
//  1. current-height replies are never absent (establish-then-answer), and
//  2. the ANSWER always describes the COMMITTED clock -- the same one GetStoreHash's hashes
//     describe -- even in the never-committed window, where the enclave's own startup writes
//     already sit in the cache.  Answering from the cache there made the seam report the two
//     mechanisms disagreeing when each was honestly reading a different commit point.
func TestGetStoreAccumulatorsAnswersTheCommittedClock(t *testing.T) {
	s := newTestEnclaveServer(t)

	// Rows in the CACHE only -- the first-boot shape (the enclave writes its own identity and
	// keys before anything commits).
	putWallet(s, "w1")
	putWallet(s, "w2")

	r, err := s.GetStoreAccumulators(context.Background(), &types.MsgGetStoreAccumulators{})
	require.NoError(t, err)
	require.Len(t, r.Accumulators, len(storeHashKeys), "every mirrored store must be answered")
	for _, e := range r.Accumulators {
		require.True(t, e.Present, "current-height replies must never be absent: "+e.Key)
		if e.Key == types.WalletKeyPrefix {
			require.Equal(t, make([]byte, 32), e.Acc,
				"pre-commit, the answer must be the COMMITTED content's accumulator (empty store = zero), "+
					"not the cache's -- GetStoreHash's scan would say empty here, and the two must agree on the clock")
			require.EqualValues(t, 0, e.Rows)
		}
	}

	// The maintenance establishment DID cover the cache rows (its separate concern), so after the
	// commit the maintained row and the content land together and the answer flips to the data.
	endBlock(t, s, 5)

	r2, err := s.GetStoreAccumulators(context.Background(), &types.MsgGetStoreAccumulators{Keys: []string{types.WalletKeyPrefix}})
	require.NoError(t, err)
	require.Len(t, r2.Accumulators, 1, "the keys filter must narrow the reply")
	want := scanAcc(s, types.WalletKeyPrefix)
	require.Equal(t, want[:], r2.Accumulators[0].Acc, "post-commit, the committed row equals the data")
	require.EqualValues(t, -1, r2.Accumulators[0].Rows, "served from the maintained row, not re-scanned")
}

// Historical reads are read-only and may honestly be absent: an accumulator did not exist before
// the block that established it, and absent != zero.
func TestGetStoreAccumulatorsHistoricalIsReadOnlyAndHonestlyAbsent(t *testing.T) {
	s := newTestEnclaveServer(t)

	// Block 5 commits WITHOUT accumulators having ever been established... except endBlock now
	// runs maintainAccumulators, so establishment happens AT block 5.  Height 5 therefore has
	// values; the interesting assertion is that they are served without establishing anything new.
	putWallet(s, "w1")
	endBlock(t, s, 5)
	putWallet(s, "w2")
	endBlock(t, s, 6)

	r5, err := s.GetStoreAccumulators(context.Background(), &types.MsgGetStoreAccumulators{Keys: []string{types.WalletKeyPrefix}, Height: 5})
	require.NoError(t, err)
	require.True(t, r5.Accumulators[0].Present)
	r6, err := s.GetStoreAccumulators(context.Background(), &types.MsgGetStoreAccumulators{Keys: []string{types.WalletKeyPrefix}, Height: 6})
	require.NoError(t, err)
	require.True(t, r6.Accumulators[0].Present)
	require.NotEqual(t, r5.Accumulators[0].Acc, r6.Accumulators[0].Acc,
		"the height-5 and height-6 values must differ -- w2 was written between them; identical "+
			"values would mean the historical read is not actually pinned to the height")
}
