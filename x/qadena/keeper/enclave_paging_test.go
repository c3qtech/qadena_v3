package keeper_test

// The multi-page branches of the REAL keeper code, forced.
//
// Live chains never exercise these: a block's outbox is a handful of rows and the mirrored tables
// fit a single 1 MiB page with three orders of magnitude to spare (a full regression's largest
// drain was 16 rows, and every seed was pages=1).  The enclave-side tests in cmd/qadenad_enclave
// force paging through the ENCLAVE's handler, but they drive it with a test-local copy of the
// caller's loop -- so the keeper's own `more`-loop, its page bound, and seedEnclaveStore's
// flush-on-budget branch had never run anywhere until these.

import (
	"bytes"
	"fmt"
	"testing"

	"cosmossdk.io/log"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	keepertest "github.com/c3qtech/qadena_v3/testutil/keeper"
	"github.com/c3qtech/qadena_v3/x/qadena/keeper"
	"github.com/c3qtech/qadena_v3/x/qadena/types"

	"context"
)

// pagingEnclave returns a queue of wallets a page at a time, exactly as the paged enclave does:
// each SyncWallets call consumes some entries and reports More until the queue is empty.
type pagingEnclave struct {
	types.QadenaEnclaveClient
	queue    []*types.Wallet
	perPage  int
	calls    int
	stuck    bool // report More forever without consuming -- the runaway the page bound exists for
	returned int
}

func (f *pagingEnclave) SyncWallets(_ context.Context, in *types.MsgSyncWallets, _ ...grpc.CallOption) (*types.SyncWalletsReply, error) {
	f.calls++
	if f.stuck {
		return &types.SyncWalletsReply{Wallets: []*types.Wallet{{WalletID: "again"}}, More: true}, nil
	}
	n := f.perPage
	if n > len(f.queue) {
		n = len(f.queue)
	}
	page := f.queue[:n]
	f.queue = f.queue[n:]
	f.returned += n
	return &types.SyncWalletsReply{Wallets: page, More: len(f.queue) > 0}, nil
}

func withPagingEnclave(t *testing.T, fake types.QadenaEnclaveClient) {
	t.Helper()
	prev := keeper.EnclaveGRPCClient
	keeper.EnclaveGRPCClient = fake
	t.Cleanup(func() { keeper.EnclaveGRPCClient = prev })
}

// The keeper's drain loop must keep calling while the enclave reports More, and deliver every row
// exactly once across the pages -- the property paging must not be able to break.
func TestKeeperDrainLoopAggregatesAllPages(t *testing.T) {
	_, ctx := keepertest.QadenaKeeper(t)

	const total, perPage = 23, 5 // deliberately not a multiple: the last page is short
	fake := &pagingEnclave{perPage: perPage}
	for i := 0; i < total; i++ {
		fake.queue = append(fake.queue, &types.Wallet{WalletID: fmt.Sprintf("w%02d", i)})
	}
	withPagingEnclave(t, fake)

	err, wallets := keeper.Keeper{}.EnclaveSyncWallets(ctx)
	require.NoError(t, err)

	require.Len(t, wallets, total, "every queued row must arrive exactly once across the pages")
	seen := map[string]bool{}
	for _, w := range wallets {
		require.False(t, seen[w.WalletID], "row delivered twice: "+w.WalletID)
		seen[w.WalletID] = true
	}
	require.Equal(t, 5, fake.calls, "23 rows at 5 per page is exactly 5 calls -- more means a wasted round trip, fewer means a dropped page")
}

// The page bound is the backstop against an enclave whose More never clears.  Without it the loop
// -- which deliberately has no deadline -- would spin forever inside EndBlock, which is precisely
// the silent-hang shape the watchdog was built to kill.  The bound must produce an ERROR, not a
// truncated success: rows were consumed from queues that were then cleared, so proceeding with a
// partial drain would lose them.
func TestKeeperDrainLoopBoundsARunawayEnclave(t *testing.T) {
	_, ctx := keepertest.QadenaKeeper(t)

	var logbuf bytes.Buffer
	ctx = ctx.WithLogger(log.NewLogger(&logbuf))

	fake := &pagingEnclave{stuck: true}
	withPagingEnclave(t, fake)

	err, _ := keeper.Keeper{}.EnclaveSyncWallets(ctx)
	require.Error(t, err, "a stuck More must surface as an error, never as a silent partial drain")
	require.Contains(t, err.Error(), "did not drain", "the error must say what happened")
	require.LessOrEqual(t, fake.calls, 256, "the loop must stop at the documented bound")
	require.Greater(t, fake.calls, 200, "the bound should be the documented 256, not something tighter that real backlogs could hit")
}

// seedEnclaveStore's flush-on-budget branch: rows totalling several times the page budget must
// arrive as several pages, none of them (except a single oversize row) exceeding the budget, and
// every row exactly once.  This is the branch no real table has ever been big enough to reach.
func TestMirrorSeedSplitsAnOversizeTableIntoPages(t *testing.T) {
	k, ctx := keepertest.QadenaKeeper(t)

	// ~2.8 MiB of wallet rows against a 1 MiB budget: forces at least 3 pages through the REAL
	// iterator + flush path, with row sizes big enough that page boundaries land mid-table.
	const rows, rowSize = 12, 240 << 10
	blob := bytes.Repeat([]byte{0x51}, rowSize)
	for i := 0; i < rows; i++ {
		k.SetWalletNoEnclave(ctx, types.Wallet{
			WalletID: fmt.Sprintf("big-wallet-%02d", i),
			// A []byte field that survives the Wallet -> StableWallet conversion inside
			// SetWalletNoEnclave verbatim, so the STORED row really is this big.
			EncCreateWalletVShare: blob,
		})
	}

	fake := withDivergentEnclave(t, nil)
	fake.accs = map[string][]byte{types.WalletKeyPrefix: bytes.Repeat([]byte{0x5e}, 32)} // wrong, so it seeds

	require.NoError(t, k.EnclaveSynchronizeStoresForTest(ctx))

	require.GreaterOrEqual(t, len(fake.pages), 3, "2.8 MiB against a 1 MiB budget must produce at least 3 pages")
	total := 0
	for _, p := range fake.pages {
		require.Equal(t, types.WalletKeyPrefix, p.GetKey())
		size := 0
		for _, r := range p.GetRows() {
			size += len(r)
		}
		if len(p.GetRows()) > 1 {
			require.LessOrEqual(t, size, 1<<20, "a multi-row page must respect the budget")
		}
		total += len(p.GetRows())
	}
	require.Equal(t, rows, total, "every row exactly once across the pages")
}
