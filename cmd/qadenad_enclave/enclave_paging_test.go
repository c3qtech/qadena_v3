package main

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	dsvstypes "github.com/c3qtech/qadena_v3/x/dsvs/types"
	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

// drainWallets is the caller's side of the paging contract -- the loop EnclaveSyncWallets runs --
// so the tests below exercise the same shape the chain does rather than a convenient approximation.
func drainWallets(t *testing.T, s *qadenaServer, maxBytes uint32) (all []string, pages int) {
	t.Helper()
	for pages = 1; ; pages++ {
		require.Less(t, pages, 100, "drain did not terminate -- `more` is stuck true")

		reply, err := s.SyncWallets(context.Background(), &types.MsgSyncWallets{Clear: true, MaxBytes: maxBytes})
		require.NoError(t, err)
		for _, w := range reply.Wallets {
			all = append(all, w.WalletID)
		}
		if !reply.More {
			return all, pages
		}
	}
}

// The property that matters: paging changes how many calls it takes, never what comes back.  Every
// queued row is delivered EXACTLY once across the pages, and the queue ends empty.
func TestPagedDrainDeliversEveryRowExactlyOnce(t *testing.T) {
	s := newTestEnclaveServer(t)

	const n = 40
	want := map[string]bool{}
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("wallet-%02d", i)
		s.setWallet(types.Wallet{WalletID: id})
		want[id] = true
	}
	require.Len(t, outboxGet[string](s, outboxWalletsKey), n)

	// A budget far below one row's size, so every page carries a single row and the paging path is
	// forced rather than incidental.
	got, pages := drainWallets(t, s, 1)

	require.Greater(t, pages, 1, "the budget should have forced more than one page")
	require.Len(t, got, n, "a row was dropped or delivered twice")
	for _, id := range got {
		require.True(t, want[id], "unexpected row "+id)
		delete(want, id)
	}
	require.Empty(t, want, "rows never delivered")
	require.Empty(t, outboxGet[string](s, outboxWalletsKey), "the queue should be drained")
}

// A row larger than the whole budget must still go, alone.  Otherwise the smallest possible budget
// wedges the queue permanently -- the page would always be empty and `more` always true.
func TestOversizeRowStillMakesProgress(t *testing.T) {
	s := newTestEnclaveServer(t)
	s.setWallet(types.Wallet{WalletID: "single"})

	got, _ := drainWallets(t, s, 1)
	require.Equal(t, []string{"single"}, got)
	require.Empty(t, outboxGet[string](s, outboxWalletsKey))
}

// Everything fitting in one page must NOT ask for another.  This is the common case, and a stray
// `more` here would double every drain's cost.
func TestSinglePageDrainDoesNotAskForMore(t *testing.T) {
	s := newTestEnclaveServer(t)
	s.setWallet(types.Wallet{WalletID: "w1"})
	s.setWallet(types.Wallet{WalletID: "w2"})

	reply, err := s.SyncWallets(context.Background(), &types.MsgSyncWallets{Clear: true})
	require.NoError(t, err)
	require.Len(t, reply.Wallets, 2)
	require.False(t, reply.More, "a fully drained queue must not report more work")
}

// A DIAGNOSTIC READ MUST NOT LOOP.  With Clear unset the queue does not shrink, so a `more` here
// would spin a caller forever against a queue that can never empty.
func TestUnclearedDrainNeverReportsMore(t *testing.T) {
	s := newTestEnclaveServer(t)
	for i := 0; i < 20; i++ {
		s.setWallet(types.Wallet{WalletID: fmt.Sprintf("w%d", i)})
	}

	reply, err := s.SyncWallets(context.Background(), &types.MsgSyncWallets{Clear: false, MaxBytes: 1})
	require.NoError(t, err)
	require.NotEmpty(t, reply.Wallets)
	require.False(t, reply.More, "a read that clears nothing must not ask to be called again")
	require.Len(t, outboxGet[string](s, outboxWalletsKey), 20, "nothing should have been consumed")
}

// An entry whose row has gone must not stall the drain.  `more` means "stopped early", not "queue
// non-empty", and this is the case that distinguishes them: the queue still holds the dead entry
// after a full walk, and the caller must still be told to stop.
func TestUnresolvableEntryDoesNotStallTheDrain(t *testing.T) {
	s := newTestEnclaveServer(t)

	outboxAppend(s, outboxWalletsKey, "never-existed")
	s.setWallet(types.Wallet{WalletID: "real"})

	got, pages := drainWallets(t, s, 1)
	require.Equal(t, []string{"real"}, got, "only the resolvable row should be delivered")
	require.LessOrEqual(t, pages, 3)
}

// Seeding must go through the handlers, and the handler is what makes a row visible to getWallet.
// A page written straight into the store would leave this passing while the derived indexes the
// handlers build were silently skipped -- the CredentialPCXY failure exactly.
func TestSeedStorePageAppliesRowsThroughTheHandler(t *testing.T) {
	s := newTestEnclaveServer(t)

	page := &types.MsgSeedStorePage{Key: types.WalletKeyPrefix}
	for i := 0; i < 5; i++ {
		w := types.Wallet{WalletID: fmt.Sprintf("seeded-%d", i)}
		b, err := w.Marshal()
		require.NoError(t, err)
		page.Rows = append(page.Rows, b)
	}

	reply, err := s.SeedStorePage(context.Background(), page)
	require.NoError(t, err)
	require.EqualValues(t, 5, reply.Accepted)
	require.EqualValues(t, 0, reply.Failed)

	for i := 0; i < 5; i++ {
		_, found := s.getWallet(fmt.Sprintf("seeded-%d", i))
		require.True(t, found, "seeded row did not reach the store")
	}
}

// EVERY STORE THE ENCLAVE HASHES MUST BE SEEDABLE, or the chain finds it out of sync, has no way to
// repair it, and reports OUT-OF-SYNC on that store forever.
//
// This is the PioneerJar bug written as an assertion.  Writes to that store had always been
// forwarded to the enclave, so the mirror looked complete -- but the store was missing from the
// seed set, so a node that never EXECUTED the block creating the jar never got it, and a
// state-synced joiner sat at 0 rows against the primary's 1 with the row on its own disk the whole
// time.  Nothing was broken except a list that had fallen behind another list.
func TestEverySeedableStoreHasAHandler(t *testing.T) {
	for _, key := range storeHashKeys {
		if key == dsvstypes.AuthorizedSignatoryKeyPrefix {
			continue // seeded by the dsvs keeper, deliberately absent here
		}
		require.Contains(t, seedHandlers, key,
			"store "+key+" is hashed but cannot be seeded, so a mismatch on it could never be repaired")
	}
}

// The converse: a handler for a store nobody hashes is never invoked, because seeding is only
// triggered by a hash mismatch.  It is dead code that looks like coverage.
func TestEveryHandlerCorrespondsToAHashedStore(t *testing.T) {
	hashed := map[string]bool{}
	for _, key := range storeHashKeys {
		hashed[key] = true
	}
	for key := range seedHandlers {
		require.True(t, hashed[key],
			"store "+key+" has a seed handler but is never hashed, so the handler can never run")
	}
}

// An unseedable store must FAIL, not be skipped.  A skip is indistinguishable from a successful
// seed at the caller and leaves the store empty -- the same silent shape as PioneerJar's missing
// mirror entry, which cost a state-synced joiner a row it already had on disk.
func TestSeedStorePageRejectsAnUnknownStore(t *testing.T) {
	s := newTestEnclaveServer(t)

	_, err := s.SeedStorePage(context.Background(), &types.MsgSeedStorePage{
		Key:  "NotAStore/value/",
		Rows: [][]byte{{0x01}},
	})
	require.Error(t, err, "an unknown store must not report a successful seed")
}

// Undecodable rows are counted rather than aborting the page, and the caller turns any non-zero
// count into a refusal to continue.  Counting the whole page tells the operator how much is wrong;
// stopping at the first bad row would make that depend on where in the page it sat.
func TestSeedStorePageCountsBadRowsWithoutAbandoningThePage(t *testing.T) {
	s := newTestEnclaveServer(t)

	good, err := (&types.Wallet{WalletID: "good"}).Marshal()
	require.NoError(t, err)

	reply, err := s.SeedStorePage(context.Background(), &types.MsgSeedStorePage{
		Key: types.WalletKeyPrefix,
		// A trailing field tag promising far more bytes than follow: not decodable as a Wallet.
		Rows: [][]byte{good, {0x0a, 0x7f}},
	})
	require.NoError(t, err)
	require.EqualValues(t, 1, reply.Accepted)
	require.EqualValues(t, 1, reply.Failed)

	_, found := s.getWallet("good")
	require.True(t, found, "the good row in the page should still have been applied")
}
