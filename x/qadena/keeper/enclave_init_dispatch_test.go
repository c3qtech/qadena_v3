package keeper_test

// The startup init gate, and specifically the case that got past review and only failed on a real
// two-node join: A JOINER MUST NOT RE-INITIALIZE ITS ENCLAVE.
//
// The bug was subtle because every cheap signal agrees with the wrong answer.  A joiner block-syncs
// from genesis, so it EXECUTES BLOCK 2 -- and at that point in history there is no JarRegulator row,
// because the row is created a few blocks later.  The gate read chain state, saw no row, and
// dispatched, on a node whose enclave `sync-enclave` had fully initialized minutes earlier.  It was
// harmless only because InitEnclave happens to be idempotent; the same code path on an enclave with
// no params would have minted a second jar and regulator and OVERWRITTEN the chain's, making every
// suspicious-transaction report ever filed undecryptable.
//
// So the gate asks the enclave, which is the only party that knows and the only answer that does
// not rewind during replay.  These tests pin that: initialized enclave -> never dispatch, however
// inviting the chain state looks.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	keepertest "github.com/c3qtech/qadena_v3/testutil/keeper"
	"github.com/c3qtech/qadena_v3/x/qadena/keeper"
	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

// statusEnclave answers GetEnclaveStatus however the test dictates, and counts the calls.  The
// embedded nil interface makes any unmodelled RPC panic rather than quietly succeed.
type statusEnclave struct {
	types.QadenaEnclaveClient
	initialized   bool
	pioneerID     string
	unimplemented bool
	statusCalls   int
}

func (f *statusEnclave) GetEnclaveStatus(_ context.Context, _ *types.MsgGetEnclaveStatus, _ ...grpc.CallOption) (*types.GetEnclaveStatusReply, error) {
	f.statusCalls++
	if f.unimplemented {
		return nil, status.Error(codes.Unimplemented, "unknown method GetEnclaveStatus")
	}
	return &types.GetEnclaveStatusReply{Initialized: f.initialized, PioneerID: f.pioneerID}, nil
}

func withStatusEnclave(t *testing.T, fake *statusEnclave) {
	t.Helper()
	prev := keeper.EnclaveGRPCClient
	keeper.EnclaveGRPCClient = fake
	keeper.ResetInitEnclaveDispatchForTest()
	t.Cleanup(func() {
		keeper.EnclaveGRPCClient = prev
		keeper.ResetInitEnclaveDispatchForTest()
	})
}

// THE REGRESSION.  Chain state says "no JarRegulator" (as it does at replay height 2 on every
// joiner) and the block is live, so every other gate is open -- but the enclave says it is already
// initialized, and that has to be the end of it.
func TestJoinerWithInitializedEnclaveNeverDispatches(t *testing.T) {
	k, ctx := keepertest.QadenaKeeper(t)
	ctx = ctx.WithBlockHeight(2).WithBlockTime(time.Now())

	fake := &statusEnclave{initialized: true, pioneerID: "pioneer3"}
	withStatusEnclave(t, fake)

	dispatched := 0
	keeper.ArmInitEnclaveDispatch("jar1", func() error { dispatched++; return nil })

	k.MaybeDispatchInitEnclave(ctx)
	require.Equal(t, 0, dispatched,
		"an enclave that reports itself initialized must never be told to initialize again -- this is the joiner case, where sync-enclave set it up before the node started")
	require.Equal(t, 1, fake.statusCalls, "the enclave must actually have been asked")

	// And it must stay decided: later blocks must not re-ask or re-dispatch.
	for h := int64(3); h < 40; h++ {
		k.MaybeDispatchInitEnclave(ctx.WithBlockHeight(h).WithBlockTime(time.Now()))
	}
	require.Equal(t, 0, dispatched, "still no dispatch on later blocks")
	require.Equal(t, 1, fake.statusCalls, "the answer is permanent; asking once is enough")
}

// The control: a genuine first pioneer on a fresh chain.  Same inviting chain state, but the
// enclave says it holds nothing -- so this one MUST dispatch, or no chain could ever start.
func TestFreshPioneerWithUninitializedEnclaveDispatches(t *testing.T) {
	k, ctx := keepertest.QadenaKeeper(t)
	ctx = ctx.WithBlockHeight(2).WithBlockTime(time.Now())

	fake := &statusEnclave{initialized: false}
	withStatusEnclave(t, fake)

	dispatched := 0
	keeper.ArmInitEnclaveDispatch("jar1", func() error { dispatched++; return nil })

	k.MaybeDispatchInitEnclave(ctx)
	require.Eventually(t, func() bool { return dispatched == 1 }, 2*time.Second, 10*time.Millisecond,
		"a fresh chain whose enclave holds no params is exactly what this gate exists to initialize")
}

// REPLAYED HISTORY IS NOT AN INVITATION.  The block is old, so the node is re-executing history --
// the case an enclave query alone cannot cover, because an enclave whose state was wiped answers
// "not initialized" no matter which block is being replayed.
func TestReplayedBlocksNeverDispatch(t *testing.T) {
	k, ctx := keepertest.QadenaKeeper(t)
	// A block from an hour ago: unambiguously history, not something being produced now.
	ctx = ctx.WithBlockHeight(2).WithBlockTime(time.Now().Add(-time.Hour))

	fake := &statusEnclave{initialized: false} // the dangerous shape: nothing to stop it but this
	withStatusEnclave(t, fake)

	dispatched := 0
	keeper.ArmInitEnclaveDispatch("jar1", func() error { dispatched++; return nil })

	k.MaybeDispatchInitEnclave(ctx)
	require.Equal(t, 0, dispatched,
		"re-executing an old block must not trigger initialization: on an established chain that would mint a second jar and regulator and overwrite the chain's")
	require.Equal(t, 0, fake.statusCalls, "and it should not even have needed to ask")
}

// An enclave too old to know the question must not be read as saying "no".  Unimplemented means
// "cannot tell", so the gate falls through to dispatching and leans on InitEnclave's idempotence --
// the behaviour that existed before the RPC did.
func TestOlderEnclaveFallsBackToDispatching(t *testing.T) {
	k, ctx := keepertest.QadenaKeeper(t)
	ctx = ctx.WithBlockHeight(2).WithBlockTime(time.Now())

	fake := &statusEnclave{unimplemented: true}
	withStatusEnclave(t, fake)

	dispatched := 0
	keeper.ArmInitEnclaveDispatch("jar1", func() error { dispatched++; return nil })

	k.MaybeDispatchInitEnclave(ctx)
	require.Eventually(t, func() bool { return dispatched == 1 }, 2*time.Second, 10*time.Millisecond,
		"an enclave that cannot answer must not silently prevent a fresh chain from initializing")
}
