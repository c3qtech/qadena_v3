package main

// The PioneerJar key bug, pinned.
//
// The enclave used to STORE the jar by JarID while its own getPioneerJar READS by PioneerID and
// the chain stores by PioneerID.  Same value, different key: the store hashes could never agree,
// so every restart reported PioneerJar OUT-OF-SYNC, the seed pushed the row (which the enclave
// re-filed under the wrong key again), and DIVERGED AT AN AGREED HEIGHT fired on a chain where
// nothing had diverged -- observed as a permanent false alarm on 2026-08-16, and the real cause
// of the enclave-rollback suite failure.  It was also data loss in waiting: two pioneers sharing
// a jar would overwrite each other's row.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"cosmossdk.io/store/prefix"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"
	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

func TestPioneerJarIsKeyedByPioneerIDLikeTheChain(t *testing.T) {
	s := newTestEnclaveServer(t)

	_, err := s.SetPioneerJar(context.Background(), &types.PioneerJar{PioneerID: "pioneer1", JarID: "jar1"})
	require.NoError(t, err)

	// The enclave's own reader takes a pioneerID; a row it cannot find is a row that effectively
	// does not exist, whatever the store holds.
	_, found := s.getPioneerJar("pioneer1")
	require.True(t, found, "the jar must be readable by PioneerID -- the key getPioneerJar and the chain both use")

	// And the raw key must be the PioneerID one, because the store HASH covers keys: a row filed
	// under any other key can never hash-match the chain's copy, however identical the value.
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(types.PioneerJarKeyPrefix))
	require.NotNil(t, store.Get(types.PioneerJarKey("pioneer1")), "stored under the chain's key")
	require.Nil(t, store.Get(types.PioneerJarKey("jar1")), "nothing may be filed under the JarID key")
}

// An enclave that already holds the row under the OLD key must shed it on the next write, or the
// extra row keeps the hashes apart forever and the false alarm survives the fix.
func TestPioneerJarLegacyJarIDRowIsCleanedUp(t *testing.T) {
	s := newTestEnclaveServer(t)
	s.ensureAccumulator(types.PioneerJarKeyPrefix)

	// Plant the pre-fix state: the same jar, filed under JarID, through the old write path's
	// exact shape (accumulated, then set).
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(types.PioneerJarKeyPrefix))
	jar := types.PioneerJar{PioneerID: "pioneer1", JarID: "jar1"}
	legacy := s.Cdc.MustMarshal(&jar)
	s.accumulateWrite(types.PioneerJarKeyPrefix, types.PioneerJarKey("jar1"), legacy)
	store.Set(types.PioneerJarKey("jar1"), legacy)

	// The next chain-driven write -- a seed, or any SetPioneerJar -- self-heals.
	_, err := s.SetPioneerJar(context.Background(), &jar)
	require.NoError(t, err)

	require.Nil(t, store.Get(types.PioneerJarKey("jar1")), "the legacy JarID row must be deleted")
	require.NotNil(t, store.Get(types.PioneerJarKey("pioneer1")))
	require.Len(t, s.getAllPioneerJars(), 1, "exactly one row after healing, not a legacy duplicate")

	// The accumulator must have followed the delete+rewrite exactly, or the shadow reports a
	// mismatch caused by its own repair.
	maintained, ok := s.loadAccumulator(types.PioneerJarKeyPrefix)
	require.True(t, ok)
	acc, _ := c.AccumulatorFromPrefixStore(store)
	require.Equal(t, acc, maintained, "the cleanup must keep the shadow accumulator consistent")
}
