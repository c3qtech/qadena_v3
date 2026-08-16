package keeper

// Contexts for calls into the enclave.
//
// The distinction here is consensus-critical, and it is the fix for the 2026-08-13 fork at height
// 34,025 (archived on pioneer2 as ~/qadena-fork-20260814).
//
// Every enclave call used to be made under `context.WithTimeout(..., c.DebugTimeout)` -- a hardcoded
// TWO SECOND wall-clock deadline. Most of those calls happen inside deterministic state-machine
// execution: message handlers, BeginBlock/EndBlock, and the PostHandler. A wall-clock deadline there
// is a fork waiting to happen, because whether it fires depends on how loaded the machine is, not on
// the chain's data.
//
// That is exactly what happened. Under block-sync catch-up load, `TransactionComplete` exceeded the
// deadline for one transaction. `EndTransaction` returned the error, `PostHandle` propagated it, and
// per baseapp.go:988 ("If the postHandler fails, we also revert the runMsgs state") the transaction's
// writes were discarded -- while the ante handler's fee, already committed at baseapp.go:955, stayed.
// A successful transaction became a failed one on ONE node, which then computed a different app hash
// and was ejected from the network. The same node, on an earlier run at real-time pace, had executed
// the very same block correctly.
//
// So: no call that can influence execution may carry a wall-clock deadline. Queries may, and should
// -- their results never reach consensus, and a stuck enclave must not hang the RPC server.
//
// The default is deliberately the safe one. A new call site that reaches for enclaveExecContext gets
// fork-safety for free; using the query variant is the choice you have to make on purpose.
//
// Note this file lives in the keeper package on purpose. `cmd/qadenad_enclave` does not import the
// keeper, so changes here cannot perturb the enclave binary or its measurement -- which genesis
// records, and which a running network cannot have change underneath it.

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"cosmossdk.io/log"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"google.golang.org/grpc"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"
	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

// enclaveAlive is cancelled ONCE, by the watchdog, when the enclave has stopped serving anything.
// Every execution-path context derives from it, so a call blocked inside a wedged enclave unblocks
// with a cancellation and reaches haltOnEnclaveFailure -- the loud, intended halt -- instead of
// hanging forever with nothing in the log.
//
// This is the counterpart to removing the wall-clock deadline (the height-34,025 fix, above).
// Removing the deadline was right, but it made a DEAD enclave indistinguishable from a busy one:
// the node froze silently, with no panic, no height and no reason anywhere.  Liveness is a separate
// question from latency, so it is asked separately -- by the watchdog, off the consensus path --
// and the answer arrives here, as a cancellation whose cause names what actually happened.
var (
	enclaveAlive       context.Context
	enclaveAliveCancel context.CancelCauseFunc
)

func init() { resetEnclaveAliveForTesting() }

// resetEnclaveAliveForTesting re-arms the root.  Production arms it exactly once, via init;
// tests that fire the watchdog need a fresh root afterwards or every later test inherits the
// cancellation.
func resetEnclaveAliveForTesting() {
	enclaveAlive, enclaveAliveCancel = context.WithCancelCause(context.Background())
}

// EnclaveAliveContext exposes the root for the dsvs keeper, whose enclave_call_context.go is a
// deliberate duplicate of this file's exec tier (it cannot live in x/qadena/common without
// perturbing the enclave measurement).  dsvs's calls run from ITS BeginBlock, so without this a
// stopped enclave could leave the node blocked there -- a door the cancellation would never reach.
func EnclaveAliveContext() context.Context { return enclaveAlive }

// enclaveSlowCallThreshold is the deadline that used to be enforced here. It is no longer enforced
// on the execution path, but a call that exceeds it is still worth shouting about: it is a call that
// would previously have forked this node off the network. Crossing it is a performance problem now
// rather than a correctness one, and we want it visible in the logs either way.
const enclaveSlowCallThreshold = 2 * time.Second

// enclaveExecContext returns the context for an enclave call made from inside deterministic
// state-machine execution -- message handlers, BeginBlock/EndBlock, ante/post handlers.
//
// It carries NO wall-clock deadline, by design. The node will wait as long as the enclave takes.
// That trades a fork for a stall: a genuinely wedged enclave now stops this node instead of silently
// diverging from the network. A stalled node is loud, recoverable, and cannot corrupt state; a
// forked one is none of those.
// It derives from enclaveAlive rather than context.Background(), which is the one exception to
// "no deadline": not a timer, but the watchdog's considered verdict that the enclave is GONE.  If
// that verdict arrives while a message handler's call is in flight, the transaction fails on this
// node only -- and that still cannot fork it, because EndBlock's own sync calls then fail the same
// way and haltOnEnclaveFailure panics before the block commits.  Cancellation converts a silent
// hang into a named halt, never into divergent committed state.
func enclaveExecContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(enclaveAlive)
	start := time.Now()
	return ctx, func() {
		cancel()
		recordEnclaveCallDuration(time.Since(start))
	}
}

// Slow-call accounting.
//
// Removing the deadline means a call that would previously have forked this node now merely takes a
// while, silently. That is the right behaviour and the wrong amount of visibility: we still want to
// know when we cross the old threshold, both to catch a degrading enclave and -- immediately -- to
// have positive evidence that a clean re-sync actually exercised this hazard rather than just
// getting lucky. The fork is non-deterministic, so "it synced fine" on its own proves nothing.
//
// Every enclaveExecContext caller already does `defer cancel()`, so timing rides along for free
// without touching the call sites.
var (
	slowEnclaveCalls   atomic.Int64
	slowestEnclaveCall atomic.Int64 // nanoseconds
	slowPeerCalls      atomic.Int64
	slowestPeerCall    atomic.Int64 // nanoseconds
)

// enclavePeerSlowThreshold is an EARLY WARNING, deliberately well below enclavePeerCallTimeout.
// Waiting until calls actually hit the limit would mean the first report coincides with the first
// forked peer; a quarter of the budget gives room to react.
const enclavePeerSlowThreshold = enclavePeerCallTimeout / 4

func recordEnclaveCallDuration(d time.Duration) {
	recordInto(d, enclaveSlowCallThreshold, &slowEnclaveCalls, &slowestEnclaveCall)
}

func recordPeerCallDuration(d time.Duration) {
	recordInto(d, enclavePeerSlowThreshold, &slowPeerCalls, &slowestPeerCall)
}

func recordInto(d, threshold time.Duration, count, worst *atomic.Int64) {
	if d < threshold {
		return
	}
	count.Add(1)
	for {
		prev := worst.Load()
		if int64(d) <= prev || worst.CompareAndSwap(prev, int64(d)) {
			return
		}
	}
}

// reportSlowEnclaveCalls logs and clears the slow-call tally. Called once per block from
// EnclaveBeginBlock, so a quiet chain stays quiet in the logs.
func reportSlowEnclaveCalls(sdkctx sdk.Context) {
	if n := slowEnclaveCalls.Swap(0); n > 0 {
		worst := time.Duration(slowestEnclaveCall.Swap(0))
		c.ContextError(sdkctx, fmt.Sprintf(
			"%d execution-path enclave call(s) exceeded %s since the last block (slowest %s). "+
				"Before the height-34025 fix this would have failed a transaction on this node only "+
				"and forked it off the network.", n, enclaveSlowCallThreshold, worst))
	}
	if n := slowPeerCalls.Swap(0); n > 0 {
		worst := time.Duration(slowestPeerCall.Swap(0))
		c.ContextError(sdkctx, fmt.Sprintf(
			"%d peer-facing enclave call(s) exceeded %s (slowest %s, hard limit %s). These serve "+
				"another node's BeginBlock: if one hits the limit, THAT node diverges and nothing "+
				"in its logs will point back here.", n, enclavePeerSlowThreshold, worst, enclavePeerCallTimeout))
	}
}

// enclavePeerContext returns the context for a query THIS node serves to ANOTHER node's enclave
// WHERE THE ANSWER FEEDS THAT PEER'S DETERMINISTIC EXECUTION. Exactly three calls qualify:
//
//	EnclaveQuerySecretShare              <- peer's getSSPrivK (enclave.go:596), from the mirror
//	                                        push and transfer scanning, inside its BeginBlock
//	EnclaveQueryPrivateState             <- peer's private-state import, inside its BeginBlock
//	EnclaveQueryPrivateStateAvailability <- same
//
// The reason they need their own tier is easy to miss. The requesting enclave calls out using
// context.Background() -- no deadline on its side. The deadline that decides whether it gets an
// answer is therefore the one WE enforce, here, on OUR machine. At 2s, a loaded server silently
// changes a peer's execution and forks it, and nothing in the forked node's logs would ever point
// back at us.
//
// The deadline is kept rather than removed: an unbounded peer-facing endpoint is a denial-of-service
// surface, and timing out here cannot fork US. It is only made generous.
//
// Three calls that LOOK peer-facing are deliberately NOT here, because nothing they return gates
// anyone's execution, so a long deadline would buy nothing and widen the DoS window:
//
//	EnclaveQuerySyncEnclave             the CLI `qadenad enclave sync-enclave`, run by
//	                                    add_full_node.sh:555 BEFORE the joining node starts
//	EnclaveQueryValidateEnclaveIdentity validateEnclaveIdentities(), called from UpdateHeight
//	                                    inside `go func()` and only when IsProposer -- async,
//	                                    fire-and-forget, retried on a counter
//	EnclaveQueryRecoverKeyShare         the requesting enclave is itself serving a user query
//	                                    (QueryGetRecoverKey, enclave.go:2438), not executing
//
// All three ran at c.DebugTimeout historically and worked, and each fails loudly and retryably.
//
// CAVEAT on the 60s: it is a judgement, not a measurement. Nobody has profiled what an attested,
// Shamir-reconstructing QueryEnclaveSecretShare or a 3MiB private-state page actually costs. It
// should be re-derived from an observed p99 rather than left at a round number someone liked.
//
// And be clear about what this buys: it narrows the window, it does not close it. A peer that is
// DOWN produces exactly the same divergence as a peer that is slow. Network I/O inside deterministic
// execution cannot be made deterministic by tuning timeouts. The requester must treat a failed peer
// call as a halt rather than proceeding on partial results -- that is what actually closes the hole.
func enclavePeerContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), enclavePeerCallTimeout)
	start := time.Now()
	return ctx, func() {
		cancel()
		// Measured for the same reason as the execution path, and arguably more urgently: this is
		// the tier whose deadline gates SOMEONE ELSE'S consensus, so a call trending toward the
		// limit is the early warning that we are about to fork a peer.
		recordPeerCallDuration(time.Since(start))
	}
}

// enclavePeerCallTimeout bounds a peer-facing endpoint while being generous enough that it should
// not fire for a healthy enclave. Deliberately not derived from c.DebugTimeout -- see the caveat
// above; this number wants profiling.
const enclavePeerCallTimeout = 60 * time.Second

// enclaveQueryContext returns the context for a query that is purely local -- a user or CLI query
// served over this node's RPC, or a startup probe. A tight deadline is correct here: the result
// reaches a human, never consensus and never another node's execution, and without one a stuck
// enclave would hang the query server.
func enclaveQueryContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), time.Duration(c.DebugTimeout)*time.Second)
}

// ---------------------------------------------------------------------------------------------
// The watchdog: liveness asked as its own question, off the consensus path.
// ---------------------------------------------------------------------------------------------

// Vars rather than consts so the tests can compress time; nothing else may write them.
var (
	enclaveHealthInterval = 5 * time.Second // how often we ask
	enclaveHealthTimeout  = 3 * time.Second // SayHello does no work; this is generous already
)

// TWO THRESHOLDS, because "tell me what is wrong" and "give up" are different decisions.
//
// The FIRST missed check is logged immediately: the operator sees why the chain stopped within
// seconds, which is the whole point of this change.  Halting waits for a much longer grace, so a
// transient stall -- a slow unseal, a GC pause, a machine that swapped -- resolves itself with the
// node still running and no operator involvement.  A genuinely dead enclave still ends in the
// named panic, just later.
//
// Overridable so the crash suite can shorten it; a two-minute wait in every continuous-regression
// cycle is a real cost, and the suite is the only caller that wants the short value.  Reading an
// env var is safe here because it feeds ONLY the watchdog, which is off the consensus path -- it
// can decide when THIS node halts, never what any node computes.
//
// A var rather than a const so the tests can shorten it; nothing else may write it.
var enclaveHealthGrace = envDuration("QADENA_ENCLAVE_HEALTH_GRACE", 2*time.Minute)

func envDuration(name string, def time.Duration) time.Duration {
	if v := os.Getenv(name); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return def
}

// startEnclaveWatchdog asks the enclave whether it is alive, on a timer, entirely OFF the
// consensus path -- which is what makes its deadline safe.  A deadline that can only cancel a
// health probe cannot change state; the 2s deadline that forked height 34,025 was on a path whose
// error became a failed transaction.
//
// WHY A PING RATHER THAN A LONGER TIMEOUT ON THE CALL ITSELF.  The duration of an EndBlock
// measures the WORK, and cannot distinguish "the enclave is busy" from "the enclave is gone".  Any
// single number is wrong in both directions: short enough to detect a wedge promptly is short
// enough that ordinary load trips it, and long enough to be safe under load leaves a dead node
// silent for minutes.  SayHello takes no locks and gRPC serves it on its own goroutine, so a busy
// enclave answers it and a stopped one does not -- evidence of death, not an inference from
// elapsed time.
//
// Started once, from InitEnclave, right after the dial succeeds.  InitEnclave runs exactly once
// per process (app/app.go panics if it fails), so there is exactly one watchdog.
func startEnclaveWatchdog(logger log.Logger, conn *grpc.ClientConn) {
	go watchEnclaveLiveness(logger, types.NewGreeterClient(conn))
}

// watchEnclaveLiveness is the loop, split from the conn plumbing so the tests can stand a fake
// GreeterClient behind it.  It reads the interval each pass, so a test that compressed time and
// then restored it leaves any still-running loop probing at the production cadence.
func watchEnclaveLiveness(logger log.Logger, greeter types.GreeterClient) {
	var silentSince time.Time
	misses := 0

	for {
		time.Sleep(enclaveHealthInterval)
		ctx, cancel := context.WithTimeout(context.Background(), enclaveHealthTimeout)
		_, err := greeter.SayHello(ctx, &types.HelloRequest{Name: "watchdog"})
		cancel()

		if err == nil {
			if misses > 0 {
				// Say so explicitly.  A stall that resolved is the case the grace exists
				// for, and it should be visible rather than inferred from the logging
				// stopping.
				c.LoggerError(logger, fmt.Sprintf(
					"enclave answered again after %d missed health check(s) over %s -- not halting",
					misses, time.Since(silentSince).Round(time.Second)))
			}
			misses, silentSince = 0, time.Time{}
			continue
		}

		if misses == 0 {
			silentSince = time.Now()
		}
		misses++
		silent := time.Since(silentSince)

		// Logged from the FIRST miss: the chain is already frozen by now, because the blocked
		// EndBlock stopped commits immediately.  This is the line that says why.
		c.LoggerError(logger, fmt.Sprintf(
			"enclave missed health check %d (silent for %s, halting at %s): %v",
			misses, silent.Round(time.Second), enclaveHealthGrace, err))

		if silent < enclaveHealthGrace {
			continue
		}

		// One-way door: unblock every in-flight execution call so the halt path runs.  The
		// cause is what haltOnEnclaveFailure reports instead of a bare "context canceled".
		enclaveAliveCancel(fmt.Errorf(
			"enclave stopped responding: silent for %s across %d health checks (last: %w)",
			silent.Round(time.Second), misses, err))
		return
	}
}
