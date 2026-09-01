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
	// The backstop must be compressed too, or every test that reaches the grace pays the
	// production wait.  And enclaveExitProcess is neutered by default: a test that reaches the
	// backstop without meaning to must not take the test binary down with it.  A test that IS
	// about the backstop replaces it again after calling this.
	prevBackstop, prevExit := enclaveHaltBackstop, enclaveExitProcess
	enclaveHaltBackstop = 200 * time.Millisecond
	enclaveExitProcess = func(int) {}
	resetEnclaveAliveForTesting()
	t.Cleanup(func() {
		enclaveHealthInterval, enclaveHealthTimeout, enclaveHealthGrace = prevInterval, prevTimeout, prevGrace
		enclaveHaltBackstop, enclaveExitProcess = prevBackstop, prevExit
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

// Property 4: the cancellation is not the halt.  If it reaches no in-flight call, nothing panics
// and haltOnEnclaveFailure never runs -- the alive-root is then cancelled forever, so the node can
// never execute another block, yet it keeps running and says nothing.
//
// That is not hypothetical.  On 2026-08-25 a node sat wedged on ONE block for 4h11m in exactly this
// state, with a healthy enclave logging memstats throughout; three of thirty-six stalls in that log
// ended the same way.  The watchdog declared the enclave dead and then simply returned.
//
// So the property is: having declared it dead, the watchdog must SAY WHICH STATE THIS IS.
//
// IT MUST NOT EXIT.  It used to, so a supervisor would restart the node -- but the restart is what
// destroys the evidence.  Twice on 2026-08-29 systemd restarted this node within 5s of that exit,
// each time erasing the state that would have explained why the halt never ran.  A node that is
// silently restarted is not diagnosable; a halted one is, and a stopped height is what monitoring
// is supposed to watch anyway ("processes being up is not health").
//
// So the exit seam stays wired here PRECISELY so this test can prove the exit never happens: if
// someone reintroduces one, this fails.
func TestWatchdog_WedgedNodeStaysUpAndNamesTheState(t *testing.T) {
	compressWatchdogTime(t, 50*time.Millisecond)

	// No EndBlock in flight, so the cancellation has nothing to unblock and the halt cannot run.
	exited := make(chan int, 1)
	enclaveExitProcess = func(code int) { exited <- code }

	var buf bytes.Buffer
	go watchEnclaveLiveness(log.NewLogger(&buf), &fakeGreeter{healthy: false})

	// Long enough for the grace, the transport close and the compressed backstop to all elapse.
	time.Sleep(2 * time.Second)

	select {
	case code := <-exited:
		t.Fatalf("the watchdog must NOT exit -- the operator needs the process alive to capture "+
			"state before restarting; it exited %d", code)
	default:
	}

	// Silence is the failure this whole backstop exists to prevent, so the line is the contract.
	out := buf.String()
	if !strings.Contains(out, "enclave dead") {
		t.Fatalf("the watchdog declared the enclave dead and said nothing an operator could act "+
			"on; a wedged node with an empty log is the 4h11m incident.  got: %q", out)
	}
	// With nothing in flight this is the IDLE classification, not the wedge -- and the whole point
	// of the counters is that those two must no longer read the same.
	if !strings.Contains(out, "IDLE") {
		t.Fatalf("no call was in flight, so this must be reported as IDLE rather than as a wedge; got: %q", out)
	}
}

// And the converse: when the halt DOES run, the backstop must stay out of the way.  Exiting there
// would turn a correct, named halt into a process death the operator did not ask for.
func TestWatchdog_BackstopStaysQuietWhenTheHaltRuns(t *testing.T) {
	compressWatchdogTime(t, 50*time.Millisecond)
	withEnclaveClient(t, &blockingEnclaveClient{})

	exited := make(chan int, 1)
	enclaveExitProcess = func(code int) { exited <- code }

	go watchEnclaveLiveness(log.NewNopLogger(), &fakeGreeter{healthy: false})

	done := make(chan any, 1)
	go func() {
		defer func() { done <- recover() }()
		Keeper{}.EnclaveInvokeEndBlock(testSDKContext())
	}()

	select {
	case r := <-done:
		if r == nil {
			t.Fatal("a dead enclave must halt the node")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("EnclaveInvokeEndBlock never unblocked")
	}

	select {
	case code := <-exited:
		t.Fatalf("the halt ran, so the backstop must not exit; it exited %d", code)
	case <-time.After(time.Second): // comfortably past the compressed backstop
	}
}

// A node running on debug values must SAY so, and a node on defaults must stay silent.  Both
// knobs fail quietly when a stale export lingers (a short grace just halts earlier, tiny pages
// just cost round trips), which is exactly why shipping with them must not be silent.
func TestDebugOverridesAreAnnouncedAndDefaultsAreSilent(t *testing.T) {
	var buf syncBuffer
	announceDebugOverrides(log.NewLogger(&buf))
	if strings.Contains(buf.String(), "NON-DEFAULT") {
		t.Fatalf("a node on production defaults must announce nothing; got:\n%s", buf.String())
	}

	prev := enclaveHealthGrace
	enclaveHealthGrace = 15 * time.Second
	t.Cleanup(func() { enclaveHealthGrace = prev })

	t.Setenv("QADENA_PAGE_BUDGET", "2048")

	var buf2 syncBuffer
	announceDebugOverrides(log.NewLogger(&buf2))
	out := buf2.String()
	if !strings.Contains(out, "NON-DEFAULT watchdog grace") {
		t.Fatalf("an overridden grace must be announced; got:\n%s", out)
	}
	if !strings.Contains(out, "NON-DEFAULT page budget") {
		t.Fatalf("an overridden page budget must be announced; got:\n%s", out)
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

// Property 5: A HALT THAT IS NOT haltOnEnclaveFailure MUST STILL COUNT AS A HALT.
//
// haltOnEnclaveFailure is EndBlock-scoped -- it takes an sdk.Context and exists to stop a fork in
// the app hash.  It is not the only correct halt.  When the call the cancellation unblocks is
// App.Commit's post-commit ConfirmHeight, the node halts just as deliberately with a different
// message: the block is already durable, the app hash is already fixed, and the watermark it could
// not advance is node-local, so there is no fork to name and borrowing EndBlock's wording would be
// a lie in the log.
//
// While haltOnEnclaveFailure was the only writer of the announce bit, that halt was invisible here.
// The watchdog fell through to the "unblocked with errors, nothing halted" branch and accused a
// call site of swallowing the error -- a bug report about code that was behaving correctly.
//
// Observed 2026-08-31 on M1: a correct halt at height 11059 reported as a swallowed error, the
// crash suite matching neither panic string, no restart, and the node left halted for 10h45m while
// 17 further soak runs timed out against it.  So the property is about the BIT, not the function:
// any path that halts announces, and the watchdog classifies on that.
func TestWatchdog_HaltAnnouncedFromAnotherPathIsReportedAsHalted(t *testing.T) {
	compressWatchdogTime(t, 50*time.Millisecond)

	var buf syncBuffer
	go watchEnclaveLiveness(log.NewLogger(&buf), &fakeGreeter{healthy: false})

	// Stand in for App.Commit's ConfirmHeight panic: announce the moment the root is cancelled,
	// which is precisely when that path's blocked call unblocks with an error.  The watchdog reads
	// the bit once, enclaveHaltBackstop after the cancel, so this is the same window production
	// relies on rather than a contrived one.
	announced := make(chan error, 1)
	go func() {
		for i := 0; i < 5000; i++ {
			if context.Cause(EnclaveAliveContext()) != nil {
				announced <- AnnounceEnclaveHalt(fmt.Errorf("rpc error: code = Canceled desc = context canceled"))
				return
			}
			time.Sleep(time.Millisecond)
		}
		announced <- nil
	}()

	var reported error
	select {
	case reported = <-announced:
	case <-time.After(10 * time.Second):
		t.Fatal("the announce goroutine never returned")
	}
	if reported == nil {
		t.Fatal("the root was never cancelled, so the halt path never ran")
	}

	// A bare "context canceled" is true and useless to whoever reads the panic; the halt must
	// report WHY the enclave went away.
	if !strings.Contains(reported.Error(), "enclave stopped responding") {
		t.Fatalf("AnnounceEnclaveHalt must substitute the watchdog's recorded cause for a bare "+
			"cancellation, or the operator reads \"context canceled\" and learns nothing; got %q", reported)
	}

	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(buf.String(), "enclave dead") {
		if time.Now().After(deadline) {
			t.Fatalf("the watchdog never declared the enclave dead; log so far:\n%s", buf.String())
		}
		time.Sleep(5 * time.Millisecond)
	}

	out := buf.String()
	if !strings.Contains(out, "halt announced: YES") {
		t.Fatalf("a halt announced from OUTSIDE haltOnEnclaveFailure must still classify as halted; got: %q", out)
	}
	if strings.Contains(out, "NOTHING HALTED FOR THEM") {
		t.Fatalf("the watchdog accused a call site of swallowing the error when a halt had in fact "+
			"announced itself -- this is the 2026-08-31 misdiagnosis; got: %q", out)
	}
}
