package keeper_test

// The chain-side accumulator ACTIVATION, tested with the same three properties the enclave's
// suite pins (cmd/qadenad_enclave/enclave_accumulator_test.go), because the two halves are the
// same design in two trust domains and must not drift in behaviour either:
//
//  1. the per-block pass establishes every mirrored store's accumulator, without any traffic;
//  2. once established, the ordinary setters maintain it exactly -- verified by the shadow scan;
//  3. a write that bypasses the hooks is DETECTED, and then repaired.

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"cosmossdk.io/log"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	keepertest "github.com/c3qtech/qadena_v3/testutil/keeper"
	"github.com/c3qtech/qadena_v3/x/qadena/keeper"
	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

func TestChainMaintainEstablishesEveryMirroredAccumulator(t *testing.T) {
	k, ctx := keepertest.QadenaKeeper(t)

	// Rows first, so establishment has real content to scan -- and rows that arrived WITHOUT the
	// hooks seeing them, which is exactly the genesis/state-sync shape establishment exists for.
	for i := 0; i < 5; i++ {
		k.SetWalletNoEnclave(ctx, types.Wallet{WalletID: fmt.Sprintf("est-%d", i)})
	}

	for _, pfx := range keeper.MirroredStorePrefixesForTest() {
		_, ok := k.LoadStoreAccumulator(ctx, pfx)
		require.False(t, ok, "nothing may exist before the first block's pass: "+pfx)
	}

	k.MaintainStoreAccumulatorsForTest(ctx)

	for _, pfx := range keeper.MirroredStorePrefixesForTest() {
		_, ok := k.LoadStoreAccumulator(ctx, pfx)
		require.True(t, ok, "the per-block pass must establish every mirrored store, traffic or not: "+pfx)
	}

	// And the established values must equal the data: the audit HALTS on violation, so simply not
	// panicking at an audit height IS the assertion.
	require.NotPanics(t, func() { k.AuditStoreAccumulatorsForTest(ctx.WithBlockHeight(25)) },
		"an establishing scan must reproduce the data exactly")
}

func TestChainHooksMaintainExactlyAfterEstablishment(t *testing.T) {
	k, ctx := keepertest.QadenaKeeper(t)
	k.MaintainStoreAccumulatorsForTest(ctx)

	// Insert, overwrite, and a fresh key -- through the REAL setter, post-establishment, so every
	// change flows through the hook's subtract/add arithmetic.
	k.SetWalletNoEnclave(ctx, types.Wallet{WalletID: "w1"})
	k.SetWalletNoEnclave(ctx, types.Wallet{WalletID: "w1", HomePioneerID: "pioneer1"}) // overwrite
	k.SetWalletNoEnclave(ctx, types.Wallet{WalletID: "w2"})

	require.NotPanics(t, func() { k.AuditStoreAccumulatorsForTest(ctx.WithBlockHeight(25)) },
		"incremental maintenance must land exactly on the from-scratch scan -- the overwrite is "+
			"the classic miss (forgetting to subtract leaves both contributions in the sum forever)")
}

// An unhooked write violates the maintained invariant, and the audit's reaction is a HALT, not a
// repair: repairing would either mask the code defect forever (the unhooked path keeps corrupting
// the summary while the node quietly patches it) or bless corrupted data as the new truth.
func TestChainUnhookedWriteHaltsTheAudit(t *testing.T) {
	k, ctx := keepertest.QadenaKeeper(t)
	k.MaintainStoreAccumulatorsForTest(ctx)

	// The hazard: a row written past every setter, so no hook fires.
	k.RawStoreSetForTest(ctx, types.WalletKeyPrefix, []byte("smuggled"), []byte("row"))

	// Off-cadence heights do not audit -- the invariant is checked every Nth block, not every one.
	require.NotPanics(t, func() { k.AuditStoreAccumulatorsForTest(ctx.WithBlockHeight(26)) })

	var got interface{}
	func() {
		defer func() { got = recover() }()
		k.AuditStoreAccumulatorsForTest(ctx.WithBlockHeight(50))
	}()
	require.NotNil(t, got, "the audit must halt on a violated invariant")
	msg := fmt.Sprint(got)
	require.Contains(t, msg, "accumulator audit FAILED", "the panic is all an operator gets; it must say what happened")
	require.Contains(t, msg, types.WalletKeyPrefix, "and name the store")
	require.Contains(t, msg, "halting rather than repairing", "and say why it did not silently fix it")
}

// endBlockEnclave models the per-block ride-along: EndBlock succeeds and returns whatever
// accumulators the test dictates.  Embedded nil interface panics on anything unmodelled.
type endBlockEnclave struct {
	types.QadenaEnclaveClient
	entries []*types.StoreAccumulatorEntry
}

func (f *endBlockEnclave) EndBlock(_ context.Context, _ *types.MsgEndBlock, _ ...grpc.CallOption) (*types.EndBlockReply, error) {
	return &types.EndBlockReply{PreparedHeight: 1, Version: 1, Accumulators: f.entries}, nil
}

// The every-block check, both directions: agreement stays quiet, divergence is named -- and an
// old enclave that predates the field (empty list) is tolerated silently, which is what lets the
// two binaries cross the upgrade window without the chain screaming at its own enclave.
func TestPerBlockAccumulatorComparison(t *testing.T) {
	k, ctx := keepertest.QadenaKeeper(t)
	k.SetWalletNoEnclave(ctx, types.Wallet{WalletID: "pb-w"})
	k.MaintainStoreAccumulatorsForTest(ctx)
	chainAcc, ok := k.LoadStoreAccumulator(ctx, types.WalletKeyPrefix)
	require.True(t, ok)

	prev := keeper.EnclaveGRPCClient
	t.Cleanup(func() { keeper.EnclaveGRPCClient = prev })

	// Agreement: the enclave reports the same value the chain holds.
	var quiet bytes.Buffer
	keeper.EnclaveGRPCClient = &endBlockEnclave{entries: []*types.StoreAccumulatorEntry{
		{Key: types.WalletKeyPrefix, Acc: chainAcc[:], Present: true},
	}}
	k.EnclaveInvokeEndBlock(ctx.WithLogger(log.NewLogger(&quiet)))
	require.NotContains(t, quiet.String(), "PER-BLOCK ACC DIVERGENCE")

	// Divergence ON A LIVE BLOCK: named, with the store and both sides.
	//
	// The block time is now load-bearing and has to be set explicitly.  A joining node diverges on
	// every block of its catch-up -- 1,806 ERROR lines on a block-sync join, 410 on a state-sync one,
	// all of them expected -- so those are counted and reported once instead (see the catch-up case
	// below).  A test context has a zero BlockTime, which reads as replaying, so a test that means
	// "live" must say so.
	var loud bytes.Buffer
	liveCtx := ctx.WithBlockTime(time.Now()).WithLogger(log.NewLogger(&loud))
	keeper.EnclaveGRPCClient = &endBlockEnclave{entries: []*types.StoreAccumulatorEntry{
		{Key: types.WalletKeyPrefix, Acc: bytes.Repeat([]byte{0xd1}, 32), Present: true},
	}}
	k.EnclaveInvokeEndBlock(liveCtx)
	require.Contains(t, loud.String(), "PER-BLOCK ACC DIVERGENCE",
		"chain and enclave committing different content for the same block must be named")

	// Divergence WHILE CATCHING UP: counted, not shouted per block -- then reported once, with the
	// count and the store, when the node goes live.
	//
	// This is the case that produced ~1,800 ERROR lines a joiner could do nothing about, on a check
	// whose whole value is being believed when it fires.  Nothing is hidden: the tally names the
	// store and says whether it resolved.
	var replaying bytes.Buffer
	staleCtx := ctx.WithBlockTime(time.Now().Add(-time.Hour)).WithLogger(log.NewLogger(&replaying))
	keeper.EnclaveGRPCClient = &endBlockEnclave{entries: []*types.StoreAccumulatorEntry{
		{Key: types.WalletKeyPrefix, Acc: bytes.Repeat([]byte{0xd2}, 32), Present: true},
	}}
	k.EnclaveInvokeEndBlock(staleCtx)
	require.NotContains(t, replaying.String(), "PER-BLOCK ACC DIVERGENCE",
		"a replaying node must not emit a per-block error for divergence it cannot act on")

	// Going live: the window is reported once, naming the store and the count.
	var resolved bytes.Buffer
	keeper.EnclaveGRPCClient = &endBlockEnclave{entries: []*types.StoreAccumulatorEntry{
		{Key: types.WalletKeyPrefix, Acc: chainAcc[:], Present: true},
	}}
	k.EnclaveInvokeEndBlock(ctx.WithBlockTime(time.Now()).WithLogger(log.NewLogger(&resolved)))
	require.Contains(t, resolved.String(), "while catching up",
		"the catch-up divergence window must be reported once on going live, not silently dropped")
	require.Contains(t, resolved.String(), types.WalletKeyPrefix,
		"the one-line report must name which store diverged")

	// Compatibility: an empty list (pre-field enclave) runs no check and raises nothing.
	var compat bytes.Buffer
	keeper.EnclaveGRPCClient = &endBlockEnclave{}
	k.EnclaveInvokeEndBlock(ctx.WithLogger(log.NewLogger(&compat)))
	require.NotContains(t, compat.String(), "PER-BLOCK")
}
