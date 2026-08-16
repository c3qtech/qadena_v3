package keeper_test

// Injected-divergence tests: make chain and enclave content actually differ, and prove the mirror
// machinery DETECTS it, REPAIRS it, and RAISES THE ALARM -- then prove agreement stays silent.
//
// The gap these close is the positive control.  The detection path already had a day-long
// accidental demonstration (2026-08-16: the PioneerJar key bug made every restart a genuine
// stored-bytes divergence, and DIVERGED AT AN AGREED HEIGHT fired each time) -- but once that bug
// was fixed, nothing distinguished "the alarm is quiet because stores agree" from "the alarm is
// quiet because the machinery is dead".  These tests are that distinction, run on every `go test`.
//
// The injection is real: rows are written to the CHAIN's actual store (the keeper fixture backs it
// with a KVStore) through SetWalletNoEnclave -- the chain-only setter, exactly how a divergence
// arises when an enclave misses writes.  Only the transport is faked: the "enclave" is a stub
// whose reported hashes and accepted pages the test controls and records.

import (
	"bytes"
	"fmt"
	"strings"
	"sync"
	"testing"

	"cosmossdk.io/log"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	keepertest "github.com/c3qtech/qadena_v3/testutil/keeper"
	"github.com/c3qtech/qadena_v3/x/qadena/keeper"
	"github.com/c3qtech/qadena_v3/x/qadena/types"

	"context"
)

// divergentEnclave reports whatever hashes the test dictates and records every page seeded at it.
// The embedded interface is nil so any unmodelled RPC panics rather than silently succeeding.
type divergentEnclave struct {
	types.QadenaEnclaveClient
	mu     sync.Mutex
	hashes map[string]string
	accs   map[string][]byte // nil map = seam answers with no entries (advisory path)
	pages  []*types.MsgSeedStorePage
}

func (f *divergentEnclave) GetStoreAccumulators(_ context.Context, _ *types.MsgGetStoreAccumulators, _ ...grpc.CallOption) (*types.GetStoreAccumulatorsReply, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	reply := &types.GetStoreAccumulatorsReply{}
	for k, a := range f.accs {
		reply.Accumulators = append(reply.Accumulators, &types.StoreAccumulatorEntry{Key: k, Acc: a, Rows: -1, Present: true})
	}
	return reply, nil
}

func (f *divergentEnclave) GetStoreHash(_ context.Context, _ *types.MsgGetStoreHash, _ ...grpc.CallOption) (*types.GetStoreHashReply, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	reply := &types.GetStoreHashReply{}
	for k, h := range f.hashes {
		reply.Hashes = append(reply.Hashes, &types.StoreHash{Key: k, Hash: h})
	}
	return reply, nil
}

func (f *divergentEnclave) SeedStorePage(_ context.Context, page *types.MsgSeedStorePage, _ ...grpc.CallOption) (*types.SeedStorePageReply, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	// COPIED, deliberately.  seedEnclaveStore reuses its page buffer after each flush -- safe
	// against real gRPC, which has marshalled the request before the call returns, but a fake that
	// keeps the pointer would watch the rows vanish (`page.Rows = page.Rows[:0]`) and see empty
	// pages.  Copying is exactly what the wire does.
	cp := &types.MsgSeedStorePage{Key: page.GetKey(), Rows: append([][]byte(nil), page.GetRows()...)}
	f.pages = append(f.pages, cp)
	return &types.SeedStorePageReply{Accepted: uint32(len(page.GetRows()))}, nil
}

func (f *divergentEnclave) seededRows(key string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, p := range f.pages {
		if p.GetKey() == key {
			n += len(p.GetRows())
		}
	}
	return n
}

func withDivergentEnclave(t *testing.T, hashes map[string]string) *divergentEnclave {
	t.Helper()
	prev := keeper.EnclaveGRPCClient
	fake := &divergentEnclave{hashes: hashes}
	keeper.EnclaveGRPCClient = fake
	t.Cleanup(func() { keeper.EnclaveGRPCClient = prev })
	return fake
}

// The injection, end to end: the chain holds rows the enclave does not.  The machinery must
// notice (OUT-OF-SYNC), repair (seed exactly those rows), and -- because the two sides AGREED on
// their height -- raise the distinct alarm, since same-height different-content means something
// worse than a fresh enclave.
func TestInjectedDivergenceIsDetectedSeededAndAlarmed(t *testing.T) {
	k, ctx := keepertest.QadenaKeeper(t)

	var logbuf bytes.Buffer
	ctx = ctx.WithLogger(log.NewLogger(&logbuf))

	// The divergence: three wallets written to the chain's real store through the chain-only
	// setter.  The fake enclave reports a hash that cannot match a store with rows in it.
	for i := 0; i < 3; i++ {
		k.SetWalletNoEnclave(ctx, types.Wallet{WalletID: fmt.Sprintf("diverged-wallet-%d", i)})
	}
	require.NotEqual(t, "", k.StoreHashForTest(ctx, types.WalletKeyPrefix))

	fake := withDivergentEnclave(t, map[string]string{types.WalletKeyPrefix: "an-enclave-hash-that-matches-nothing"})

	keeper.SetEnclaveHeightsAgreedForTest(true)
	t.Cleanup(func() { keeper.SetEnclaveHeightsAgreedForTest(false) })

	require.NoError(t, k.EnclaveSynchronizeStoresForTest(ctx))

	// Detected.
	require.Contains(t, logbuf.String(), "OUT-OF-SYNC",
		"a store whose hashes differ must be reported, or the repair below happens silently")
	// Repaired: exactly the injected rows, no more, no less.
	require.Equal(t, 3, fake.seededRows(types.WalletKeyPrefix),
		"the seed must push exactly the rows the enclave is missing")
	// Alarmed: heights agreed, so this is not a fresh enclave being seeded -- say so, distinctly.
	require.Contains(t, logbuf.String(), "DIVERGED AT AN AGREED HEIGHT",
		"same height + different content must raise the distinct alarm, not read as a routine reseed")
}

// The control: identical content stays silent.  The fake reports the chain's own hash, so nothing
// may be seeded and neither message may appear -- otherwise the alarm cries wolf on every start,
// which is exactly what the PioneerJar key bug caused and what makes alarms get ignored.
func TestAgreeingStoresAreNeitherSeededNorAlarmed(t *testing.T) {
	k, ctx := keepertest.QadenaKeeper(t)

	var logbuf bytes.Buffer
	ctx = ctx.WithLogger(log.NewLogger(&logbuf))

	for i := 0; i < 3; i++ {
		k.SetWalletNoEnclave(ctx, types.Wallet{WalletID: fmt.Sprintf("agreed-wallet-%d", i)})
	}

	// A truthful enclave: it reports the hash the chain computes over its own store.
	fake := withDivergentEnclave(t, map[string]string{
		types.WalletKeyPrefix: k.StoreHashForTest(ctx, types.WalletKeyPrefix),
	})

	keeper.SetEnclaveHeightsAgreedForTest(true)
	t.Cleanup(func() { keeper.SetEnclaveHeightsAgreedForTest(false) })

	require.NoError(t, k.EnclaveSynchronizeStoresForTest(ctx))

	require.Zero(t, len(fake.pages), "agreeing stores must not be re-seeded")
	require.NotContains(t, logbuf.String(), "DIVERGED AT AN AGREED HEIGHT",
		"the alarm must stay quiet when nothing diverged -- a false alarm here is how real ones get ignored")
	if strings.Contains(logbuf.String(), "OUT-OF-SYNC") {
		t.Fatalf("no store should read OUT-OF-SYNC when hashes agree; log:\n%s", logbuf.String())
	}
}

// The seam, side by side with the scans (backlog 44 phase 1): when the enclave's accumulator
// genuinely matches the chain's, the acc verdict and the scan verdict must agree -- and when the
// two MECHANISMS disagree about the same store at the same instant, that must be screamed about,
// because it means one of them is wrong.
func TestSeamVerdictAgreesWithScanVerdict(t *testing.T) {
	k, ctx := keepertest.QadenaKeeper(t)

	var logbuf bytes.Buffer
	ctx = ctx.WithLogger(log.NewLogger(&logbuf))

	for i := 0; i < 3; i++ {
		k.SetWalletNoEnclave(ctx, types.Wallet{WalletID: fmt.Sprintf("seam-%d", i)})
	}

	// A truthful enclave on BOTH channels: scan hash and accumulator each equal the chain's own.
	k.MaintainStoreAccumulatorsForTest(ctx)
	chainAcc, ok := k.LoadStoreAccumulator(ctx, types.WalletKeyPrefix)
	require.True(t, ok)

	fake := withDivergentEnclave(t, map[string]string{
		types.WalletKeyPrefix: k.StoreHashForTest(ctx, types.WalletKeyPrefix),
	})
	fake.accs = map[string][]byte{types.WalletKeyPrefix: chainAcc[:]}

	require.NoError(t, k.EnclaveSynchronizeStoresForTest(ctx))

	require.NotContains(t, logbuf.String(), "ACC-SEAM VERDICT DISAGREES",
		"matching content on both channels must produce agreeing verdicts")
	require.NotContains(t, logbuf.String(), "ACC-SEAM enclave returned no accumulator",
		"the establish-then-answer contract means every mirrored store must be present in the reply")
	// The positive "agrees" line is DEBUG (per store per checkSync block would drown an info log);
	// liveness of the seam comparison is proven by TestSeamScreamsWhenMechanismsDisagree, so
	// absence of both failure lines here is unambiguous.
}

func TestSeamScreamsWhenMechanismsDisagree(t *testing.T) {
	k, ctx := keepertest.QadenaKeeper(t)

	var logbuf bytes.Buffer
	ctx = ctx.WithLogger(log.NewLogger(&logbuf))

	k.SetWalletNoEnclave(ctx, types.Wallet{WalletID: "seam-w"})
	k.MaintainStoreAccumulatorsForTest(ctx)

	// The pathological case: the enclave's SCAN hash matches the chain's (scan verdict: in sync)
	// but its ACCUMULATOR does not (acc verdict: differ).  One mechanism is wrong.
	fake := withDivergentEnclave(t, map[string]string{
		types.WalletKeyPrefix: k.StoreHashForTest(ctx, types.WalletKeyPrefix),
	})
	fake.accs = map[string][]byte{types.WalletKeyPrefix: bytes.Repeat([]byte{0xee}, 32)}

	require.NoError(t, k.EnclaveSynchronizeStoresForTest(ctx))

	require.Contains(t, logbuf.String(), "ACC-SEAM VERDICT DISAGREES WITH SCAN",
		"two mechanisms giving different answers about the same store at the same instant is the "+
			"one condition the side-by-side period exists to catch")
}
