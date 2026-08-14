package keeper

// Regression tests for the height-34025 fork: a wall-clock deadline on an enclave call made from
// inside deterministic execution.
//
// The fork itself is not reproducible by replaying blocks -- it was a race between a 2s deadline and
// a loaded enclave, and the same node executing the same block at real-time pace got the right
// answer. So these tests do what the incident could not: force the condition deterministically, by
// standing a deliberately slow enclave behind the client and making the deadline tiny.
//
// TestSlowEnclaveCall_OldShapeFailsTheTransaction is the important one. It fails on the pre-fix code
// by construction, which is the property a regression test for this bug has to have.

import (
	"context"
	"testing"
	"time"

	"cosmossdk.io/log"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"
	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

// slowEnclaveClient is an enclave that is simply BUSY -- not broken, not unreachable. It answers
// correctly, just later than the caller was willing to wait. That is the entire fault condition
// behind the fork, and it is why the bug is invisible in any test where the enclave is idle.
//
// The embedded interface is left nil on purpose: any RPC these tests do not explicitly model panics
// rather than silently returning a zero value.
type slowEnclaveClient struct {
	types.QadenaEnclaveClient
	delay time.Duration
	calls int
}

func (s *slowEnclaveClient) TransactionComplete(ctx context.Context, _ *types.MsgTransactionComplete, _ ...grpc.CallOption) (*types.TransactionCompleteReply, error) {
	s.calls++
	select {
	case <-time.After(s.delay):
		return &types.TransactionCompleteReply{}, nil
	case <-ctx.Done():
		// Mirrors grpc-go: a caller-side deadline surfaces as codes.DeadlineExceeded.
		return nil, status.FromContextError(ctx.Err()).Err()
	}
}

func withSlowEnclave(t *testing.T, delay time.Duration) *slowEnclaveClient {
	t.Helper()
	prev := EnclaveGRPCClient
	fake := &slowEnclaveClient{delay: delay}
	EnclaveGRPCClient = fake
	t.Cleanup(func() { EnclaveGRPCClient = prev })
	return fake
}

func testSDKContext() sdk.Context {
	return sdk.Context{}.WithLogger(log.NewNopLogger())
}

// The deadline tiers, asserted directly. These are the fix.
func TestEnclaveCallContextDeadlines(t *testing.T) {
	execCtx, cancel := enclaveExecContext()
	defer cancel()
	if deadline, ok := execCtx.Deadline(); ok {
		t.Fatalf("execution-path context must carry NO wall-clock deadline, got one at %v.\n"+
			"A deadline here decides consensus by how loaded the machine is: it fails a "+
			"transaction on this node only and forks it off the network (height 34,025).", deadline)
	}

	queryCtx, cancel := enclaveQueryContext()
	defer cancel()
	d, ok := queryCtx.Deadline()
	if !ok {
		t.Fatal("local query context must keep a deadline; without one a stuck enclave hangs the query server")
	}
	if remaining := time.Until(d); remaining > time.Duration(c.DebugTimeout)*time.Second+time.Second {
		t.Fatalf("local query deadline should track c.DebugTimeout (%ds), got %v", c.DebugTimeout, remaining)
	}

	peerCtx, cancel := enclavePeerContext()
	defer cancel()
	d, ok = peerCtx.Deadline()
	if !ok {
		t.Fatal("peer-facing context must keep a deadline -- an unbounded peer endpoint is a DoS surface")
	}
	// Generous, because the deadline we enforce here is the one that decides whether a PEER's
	// enclave gets its answer, and therefore whether the peer's execution diverges.
	if remaining := time.Until(d); remaining <= time.Duration(c.DebugTimeout)*time.Second {
		t.Fatalf("peer deadline (%v) must be far more generous than the local one (%ds): "+
			"it gates another node's execution, not ours", remaining, c.DebugTimeout)
	}
}

// The bug, forced. With the old shape -- any wall-clock deadline on the execution path -- a merely
// slow enclave turns into an error, and PostHandle turns that error into a reverted transaction
// (baseapp.go:988 "If the postHandler fails, we also revert the runMsgs state") while the ante
// handler's fee stays committed (baseapp.go:955). Different state on one node. Fork.
func TestSlowEnclaveCall_OldShapeFailsTheTransaction(t *testing.T) {
	// Production values, not a caricature: the real c.DebugTimeout against an enclave that takes
	// just over it. This is the fork condition as it actually occurred.
	fake := withSlowEnclave(t, time.Duration(c.DebugTimeout)*time.Second+500*time.Millisecond)

	// Exactly what the code used to do at all 48 call sites.
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.DebugTimeout)*time.Second)
	defer cancel()

	_, err := EnclaveGRPCClient.TransactionComplete(ctx, &types.MsgTransactionComplete{Success: true})
	if err == nil {
		t.Fatal("expected the old shape to fail on a slow enclave; if this passes the test proves nothing")
	}
	if got := status.Code(err); got != codes.DeadlineExceeded {
		t.Fatalf("expected DeadlineExceeded, got %v (%v)", got, err)
	}
	if fake.calls != 1 {
		t.Fatalf("expected exactly one call, got %d", fake.calls)
	}
}

// The fix. Same slow enclave, same transaction, through the real EndTransaction path: the call now
// waits and succeeds, so PostHandle returns nil and the transaction's writes survive.
func TestSlowEnclaveCall_ExecPathSurvives(t *testing.T) {
	// The delay MUST exceed the deadline the old code applied, or this test passes on the pre-fix
	// code too and proves nothing. That is not hypothetical: at 200ms against the old 2s deadline
	// this test was green before AND after the fix, which is exactly the false green the whole
	// height-34025 investigation kept tripping over.
	delay := enclaveSlowCallThreshold + 500*time.Millisecond
	fake := withSlowEnclave(t, delay)

	k := Keeper{}
	start := time.Now()
	err := k.EndTransaction(testSDKContext(), log.NewNopLogger(), true)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("a SLOW enclave must not fail the transaction, got %v.\n"+
			"This is the pre-fix behaviour: the deadline fires, PostHandle propagates the error, "+
			"and the transaction's writes are reverted on this node alone.", err)
	}
	if fake.calls != 1 {
		t.Fatalf("expected exactly one call, got %d", fake.calls)
	}
	// Prove it actually waited, rather than passing for some unrelated reason.
	if elapsed < delay {
		t.Fatalf("returned in %v but the enclave takes %v -- it cannot have waited, so this test is "+
			"not exercising what it claims", elapsed, delay)
	}
}

// The slow call must still be reported, or removing the deadline just trades a fork for silence.
func TestSlowEnclaveCallsAreCounted(t *testing.T) {
	slowEnclaveCalls.Store(0)
	slowestEnclaveCall.Store(0)

	recordEnclaveCallDuration(enclaveSlowCallThreshold - time.Millisecond)
	if n := slowEnclaveCalls.Load(); n != 0 {
		t.Fatalf("a call under the threshold must not be reported, got %d", n)
	}

	recordEnclaveCallDuration(enclaveSlowCallThreshold + time.Second)
	recordEnclaveCallDuration(enclaveSlowCallThreshold + 5*time.Second)
	if n := slowEnclaveCalls.Load(); n != 2 {
		t.Fatalf("expected 2 slow calls, got %d", n)
	}
	if worst := time.Duration(slowestEnclaveCall.Load()); worst != enclaveSlowCallThreshold+5*time.Second {
		t.Fatalf("expected the slowest to be retained, got %v", worst)
	}

	// Reporting clears the tally, so a quiet chain stays quiet.
	reportSlowEnclaveCalls(testSDKContext())
	if n := slowEnclaveCalls.Load(); n != 0 {
		t.Fatalf("reporting must reset the counter, got %d", n)
	}
}
