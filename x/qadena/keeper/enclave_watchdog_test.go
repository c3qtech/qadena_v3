package keeper

// Tests for the enclave watchdog: liveness asked as its own question, off the consensus path.
//
// The incident these encode: a SIGSTOPped enclave froze the chain with NOTHING in the log -- no
// panic, no height, no reason -- because execution-path calls carry no deadline (correctly, since
// height 34,025) and a call that never returns never produces the error haltOnEnclaveFailure needs.
// Observed live on 2026-08-16: the crash suite stalled the enclave, an assertion failed, and the
// node sat silently blocked for 2.5 hours.
//
// The properties, in order of importance:
//
//  1. A DEAD enclave unblocks the halt path, and the panic names the health-check cause.
//  2. A BUSY enclave is NOT halted -- the property a timeout cannot express, and the regression
//     that matters most: this is exactly the confusion that forked height 34,025.
//  3. A stall that RESOLVES within the grace never halts, and says so in the log.

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"cosmossdk.io/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"

	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

// compressWatchdogTime shrinks the probe cadence and grace so a test observes the full
// miss -> grace -> cancel arc in milliseconds, and restores everything afterwards.
//
// The restore matters beyond tidiness: watchdog loops from earlier tests may still be running
// (only a cancel ends one), and they re-read the interval each pass, so restoring it means any
// survivor idles at the production cadence instead of spinning.
func compressWatchdogTime(t *testing.T, grace time.Duration) {
	t.Helper()
	prevInterval, prevTimeout, prevGrace := enclaveHealthInterval, enclaveHealthTimeout, enclaveHealthGrace
	enclaveHealthInterval, enclaveHealthTimeout, enclaveHealthGrace = 10*time.Millisecond, 20*time.Millisecond, grace
	resetEnclaveAliveForTesting()
	t.Cleanup(func() {
		enclaveHealthInterval, enclaveHealthTimeout, enclaveHealthGrace = prevInterval, prevTimeout, prevGrace
		resetEnclaveAliveForTesting()
	})
}

// fakeGreeter answers or refuses according to `healthy`, which the test flips at will.
type fakeGreeter struct {
	mu      sync.Mutex
	healthy bool
	probes  int
}

func (g *fakeGreeter) SayHello(_ context.Context, _ *types.HelloRequest, _ ...grpc.CallOption) (*types.HelloReply, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.probes++
	if !g.healthy {
		return nil, fmt.Errorf("connection refused (fake: enclave stopped)")
	}
	return &types.HelloReply{Message: "Ping watchdog"}, nil
}

func (g *fakeGreeter) probeCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.probes
}

func (g *fakeGreeter) setHealthy(v bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.healthy = v
}

// blockingEnclaveClient models the incident's enclave: EndBlock never returns until the context is
// cancelled.  A SIGSTOPped process is exactly this from the caller's side -- no error, no reply,
// forever.  Like slowEnclaveClient above, the embedded interface is nil so any unmodelled RPC
// panics rather than silently succeeding.
type blockingEnclaveClient struct {
	types.QadenaEnclaveClient
	delay time.Duration // 0 = block until cancelled; otherwise a merely-busy enclave
}

func (b *blockingEnclaveClient) EndBlock(ctx context.Context, _ *types.MsgEndBlock, _ ...grpc.CallOption) (*types.EndBlockReply, error) {
	if b.delay > 0 {
		select {
		case <-time.After(b.delay):
			return &types.EndBlockReply{}, nil
		case <-ctx.Done():
			return nil, status.FromContextError(ctx.Err()).Err()
		}
	}
	<-ctx.Done()
	// Mirrors grpc-go: a cancelled client context surfaces as a STATUS error (codes.Canceled),
	// which does NOT unwrap to context.Canceled -- the reason haltOnEnclaveFailure consults
	// context.Cause(enclaveAlive) instead of errors.Is.
	return nil, status.FromContextError(ctx.Err()).Err()
}

func withEnclaveClient(t *testing.T, fake types.QadenaEnclaveClient) {
	t.Helper()
	prev := EnclaveGRPCClient
	EnclaveGRPCClient = fake
	t.Cleanup(func() { EnclaveGRPCClient = prev })
}

// syncBuffer lets the test read logs the watchdog goroutine is still writing.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// Property 1: the incident, replayed.  The enclave stops serving everything; EnclaveInvokeEndBlock
// is blocked inside it.  Without the watchdog this test TIMES OUT -- the call has no deadline and
// nothing ever cancels it, which is precisely the silent freeze observed live.  With it, the call
// unblocks and the halt panic names the actual cause instead of "context canceled".
func TestWatchdog_DeadEnclaveUnblocksTheHaltPath(t *testing.T) {
	compressWatchdogTime(t, 50*time.Millisecond)
	withEnclaveClient(t, &blockingEnclaveClient{})

	go watchEnclaveLiveness(log.NewNopLogger(), &fakeGreeter{healthy: false})

	done := make(chan any, 1)
	go func() {
		defer func() { done <- recover() }()
		Keeper{}.EnclaveInvokeEndBlock(testSDKContext())
	}()

	select {
	case r := <-done:
		if r == nil {
			t.Fatal("EnclaveInvokeEndBlock returned without panicking -- a dead enclave must halt the node")
		}
		msg := fmt.Sprint(r)
		if !strings.Contains(msg, "enclave stopped responding") {
			t.Fatalf("the halt must name the health-check cause, not a bare cancellation; got: %s", msg)
		}
		if !strings.Contains(msg, "halting rather than committing") {
			t.Fatalf("the halt must still carry the fork rationale; got: %s", msg)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("EnclaveInvokeEndBlock is still blocked -- the watchdog cancellation never reached it.\n" +
			"This is the pre-change behaviour: the node freezes with nothing in the log.")
	}
}

// Property 2: a busy enclave is NOT halted.  EndBlock takes far longer than the grace while
// SayHello keeps answering -- the exact combination a timeout on the call itself cannot express,
// and the confusion that forked height 34,025.  gRPC serves each RPC on its own goroutine, so
// "slow work" and "dead process" are distinguishable, and the watchdog must distinguish them.
func TestWatchdog_BusyEnclaveIsNotHalted(t *testing.T) {
	compressWatchdogTime(t, 50*time.Millisecond)
	withEnclaveClient(t, &blockingEnclaveClient{delay: 300 * time.Millisecond}) // 6x the grace

	go watchEnclaveLiveness(log.NewNopLogger(), &fakeGreeter{healthy: true})

	done := make(chan any, 1)
	go func() {
		defer func() { done <- recover() }()
		Keeper{}.EnclaveInvokeEndBlock(testSDKContext())
	}()

	select {
	case r := <-done:
		if r != nil {
			t.Fatalf("a BUSY enclave must never be halted -- it answers health checks and merely "+
				"takes a while, and halting it re-introduces the deadline-shaped fork; got panic: %v", r)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("EnclaveInvokeEndBlock never returned against a merely-busy enclave")
	}
	if cause := context.Cause(EnclaveAliveContext()); cause != nil {
		t.Fatalf("the alive-root must not be cancelled while the enclave answers probes; cause: %v", cause)
	}
}

// Property 3: a stall shorter than the grace resolves with the node still running, and the
// recovery is stated in the log rather than inferred from the complaints stopping.
func TestWatchdog_TransientStallRecoversWithoutHalting(t *testing.T) {
	compressWatchdogTime(t, 10*time.Second) // generous: this test must never reach the grace
	greeter := &fakeGreeter{healthy: false}

	var buf syncBuffer
	go watchEnclaveLiveness(log.NewLogger(&buf), greeter)

	// Let it miss a few probes, then bring the enclave back.
	deadline := time.Now().Add(3 * time.Second)
	for greeter.probeCount() < 3 {
		if time.Now().After(deadline) {
			t.Fatal("watchdog never probed the failing greeter")
		}
		time.Sleep(5 * time.Millisecond)
	}
	greeter.setHealthy(true)

	for !strings.Contains(buf.String(), "answered again") {
		if time.Now().After(deadline) {
			t.Fatalf("recovery was never logged; log so far:\n%s", buf.String())
		}
		time.Sleep(5 * time.Millisecond)
	}

	if cause := context.Cause(EnclaveAliveContext()); cause != nil {
		t.Fatalf("a stall shorter than the grace must not cancel the root; cause: %v", cause)
	}
	if !strings.Contains(buf.String(), "missed health check") {
		t.Fatal("the misses themselves must be logged from the FIRST one -- that line is the 'why' an operator sees")
	}
}

// The grace is read from the environment so the crash suite can shorten it without a rebuild; a
// garbage or negative value must fall back rather than arm a hair-trigger halt.
func TestEnvDurationFallsBackOnGarbage(t *testing.T) {
	t.Setenv("QADENA_TEST_DURATION", "not-a-duration")
	if got := envDuration("QADENA_TEST_DURATION", 2*time.Minute); got != 2*time.Minute {
		t.Fatalf("garbage must fall back to the default, got %v", got)
	}
	t.Setenv("QADENA_TEST_DURATION", "-5s")
	if got := envDuration("QADENA_TEST_DURATION", 2*time.Minute); got != 2*time.Minute {
		t.Fatalf("a non-positive duration must fall back to the default, got %v", got)
	}
	t.Setenv("QADENA_TEST_DURATION", "15s")
	if got := envDuration("QADENA_TEST_DURATION", 2*time.Minute); got != 15*time.Second {
		t.Fatalf("a valid duration must win, got %v", got)
	}
}
