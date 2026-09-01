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
	enclaveHaltAnnounced.Store(false)
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

	// How long the watchdog waits, after cancelling the root, for the halt it just triggered to
	// actually announce itself.  Only reached when the halt did NOT happen -- see the backstop at
	// the end of watchEnclaveLiveness.  Generous on purpose: when the halt works it lands within
	// milliseconds, so this never races a healthy halt.
	enclaveHaltBackstop = 5 * time.Second
)

// enclaveHaltAnnounced records that A HALT RAN for the watchdog's cancellation.  It is the
// difference between "the cancellation reached a blocked call" and "the cancellation reached
// nothing", which is invisible from inside the watchdog otherwise.
//
// IT DOES NOT MEAN "haltOnEnclaveFailure RAN", and the distinction cost a fleet.  That function is
// EndBlock-scoped: it takes an sdk.Context, names EndBlock in both strings it emits, and exists to
// stop a fork in the app hash.  App.Commit's post-commit ConfirmHeight failure is a SECOND, equally
// correct halt with none of those properties -- the block is already durable, the app hash is
// already fixed, and the watermark it could not advance is node-local -- so it rightly panics on its
// own terms rather than borrowing EndBlock's message and claiming a fork it cannot cause.
//
// While haltOnEnclaveFailure was the only writer, that second halt was invisible here.  The watchdog
// fell through to the "unblocked with errors, nothing halted" branch and accused a call site of
// swallowing the error -- sending an operator after a bug that did not exist.  Observed 2026-08-31
// on M1: a correct halt at height 11059, misreported, and the crash suite that should have restarted
// the node matched neither panic string and left it wedged for 10h45m.
//
// So it is set through AnnounceEnclaveHalt, from EVERY halt path rather than from one of them.
var enclaveHaltAnnounced atomic.Bool

// AnnounceEnclaveHalt tells the watchdog its cancellation landed, and returns the error the halt
// should REPORT: the watchdog's recorded cause when one exists, because a bare "context canceled"
// is true and useless to whoever reads the panic.
//
// Call it immediately BEFORE panicking, never after -- the panic does not return, and the watchdog
// reads the bit once, enclaveHaltBackstop after it cancels.
func AnnounceEnclaveHalt(err error) error {
	// Checked via the root's recorded cause rather than errors.Is(err, context.Canceled), because
	// gRPC surfaces the cancellation as a status error (codes.Canceled) that does not unwrap to
	// context.Canceled -- and once the root is cancelled, EVERY exec-path call fails, so whenever a
	// cause exists it is the reason this call failed.
	if cause := context.Cause(EnclaveAliveContext()); cause != nil {
		err = cause
	}
	enclaveHaltAnnounced.Store(true)
	return err
}

// WHAT THE WATCHDOG COULD NOT SEE.  enclaveHaltAnnounced is one bit, and its FALSE is ambiguous
// across four different situations: no call ever existed; a call existed and is still stuck; a
// call unblocked but nobody halted for it; or the halt is simply a moment away.  The backstop used
// to report all four as "no in-flight call existed to halt", which is true of exactly one of them
// -- and false, in the most misleading possible way, for the 4h11m wedge of 2026-08-25.
//
// These two counters make the difference measurable rather than assumed.  They are maintained by
// EnclaveInFlightInterceptor, which every dial must install, and are read ONCE by the watchdog
// when it declares the enclave dead.  Nothing reads them on the happy path and nothing logs
// per-call: a line per enclave RPC would be the log-volume problem all over again.
var (
	enclaveCallsInFlight         atomic.Int64
	enclaveCallsFailedPostCancel atomic.Int64
)

// EnclaveInFlightInterceptor counts enclave RPCs and how they ended.  EXPORTED because the real
// SGX dialler lives in cmd/qadenad and must install it too -- see the warning on that call site.
//
// STRICTLY PASS-THROUGH, and that is not a style preference.  This runs inside deterministic
// execution, so anything here that could change WHEN a call returns or WHAT it returns is a fork
// waiting to happen -- that is the height-34,025 lesson, where a two-second deadline in this path
// turned one node's successful transaction into a failed one and ejected it from the network.  Two
// atomic adds cannot change what a block computes.  A timeout, a retry, or an error rewrite could.
// Do not add any.
func EnclaveInFlightInterceptor(
	ctx context.Context, method string, req, reply any,
	cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption,
) error {
	enclaveCallsInFlight.Add(1)
	err := invoker(ctx, method, req, reply, cc, opts...)
	enclaveCallsInFlight.Add(-1)

	// "Unblocked with an error AFTER the enclave was declared dead" is the signal that separates a
	// call the cancellation/close actually reached from one still wedged.  Checked against the root
	// rather than the call's own context, because a call that missed the enclaveAlive invariant --
	// exactly the one worth counting -- has a context that was never cancelled.
	if err != nil && EnclaveAliveContext().Err() != nil {
		enclaveCallsFailedPostCancel.Add(1)
	}
	return err
}

// enclaveExitProcess is os.Exit, indirected so the watchdog tests can drive the backstop without
// killing the test binary.  Nothing but a test may replace it.
var enclaveExitProcess = os.Exit

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
	announceDebugOverrides(logger)
	// RETAINED so the backstop can close the TRANSPORT.  Cancelling enclaveAlive only reaches
	// calls that derive from it; closing the connection unblocks every in-flight call whatever
	// context it holds.  See the backstop in watchEnclaveLiveness.
	enclaveConn.Store(conn)
	go watchEnclaveLiveness(logger, types.NewGreeterClient(conn))
}

// The live connection to the enclave, retained ONLY so the watchdog's backstop can close it.
// atomic.Pointer rather than a plain var because the watchdog goroutine reads what InitEnclave's
// goroutine wrote.
var enclaveConn atomic.Pointer[grpc.ClientConn]

// closeEnclaveTransport unblocks every in-flight enclave call by tearing down the connection they
// are all waiting on, so the exec-path call that is stuck can return an error and reach
// haltOnEnclaveFailure.
//
// This is the escape hatch for the invariant the backstop exists to catch: cancellation is OPT-IN
// per call site (the context must descend from enclaveAlive), and a single call site that missed
// it hangs forever.  Closing the transport is not opt-in -- gRPC fails every RPC on a closed
// ClientConn -- so it does not depend on any call site being written correctly.
//
// Safe to call after the enclave has been declared dead: the cancel above is irreversible, so this
// node can never execute another block, and nothing is lost by dropping the connection to a process
// that has already stopped answering.
func closeEnclaveTransport(logger log.Logger) bool {
	conn := enclaveConn.Load()
	if conn == nil {
		c.LoggerError(logger, "backstop: no enclave connection retained, cannot unblock by closing the transport")
		return false
	}
	if err := conn.Close(); err != nil {
		c.LoggerError(logger, "backstop: closing the enclave transport failed: "+err.Error())
		return false
	}
	c.LoggerError(logger, "backstop: closed the enclave transport to unblock any call the cancellation did not reach")
	return true
}

// announceDebugOverrides screams once, at startup, if any env knob has this node off its
// production values.  The knobs exist for test cycles (a short grace makes the crash suite fast; a
// tiny page budget forces the multi-page paths under real traffic), and both fail QUIETLY when a
// stale export lingers -- a 15s grace just halts earlier under a real stall, tiny pages just cost
// round trips.  Quiet is the problem: a node must not ship on debug values with nothing in the log
// saying so.  ERROR level for the same reason OUT-OF-SYNC uses it -- visible at default verbosity.
func announceDebugOverrides(logger log.Logger) {
	if enclaveHealthGrace != 2*time.Minute {
		c.LoggerError(logger, fmt.Sprintf(
			"NON-DEFAULT watchdog grace %s is active (QADENA_ENCLAVE_HEALTH_GRACE) -- "+
				"intended for test cycles; a production node should not run with this set",
			enclaveHealthGrace))
	}
	if b := pageBudgetFromEnv(1 << 20); b != 1<<20 {
		c.LoggerError(logger, fmt.Sprintf(
			"NON-DEFAULT page budget %d bytes is active (QADENA_PAGE_BUDGET) -- "+
				"forced-paging is a test mode; a production node should not run with this set", b))
	}
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

		// SAMPLED BEFORE THE CANCEL, and the ordering is the whole point.  The interceptor
		// decrements when the invoker RETURNS, which happens BEFORE haltOnEnclaveFailure is
		// called -- so between the cancel and the halt there is a window where the counter reads
		// 0 and the flag is still false, even though a call was in flight and the halt is
		// microseconds away.  Reading it after the cancel would see that window and conclude
		// "idle" about a node that was mid-block.
		//
		// Sampling here is sound: against a dead enclave, calls block and never complete, so
		// nothing decrements until we cancel.  Whatever this reads is the true in-flight set.
		inFlightAtCancel := enclaveCallsInFlight.Load()
		failedBefore := enclaveCallsFailedPostCancel.Load()

		// One-way door: unblock every in-flight execution call so the halt path runs.  The
		// cause is what haltOnEnclaveFailure reports instead of a bare "context canceled".
		cause := fmt.Errorf(
			"enclave stopped responding: silent for %s across %d health checks (last: %w)",
			silent.Round(time.Second), misses, err)
		enclaveAliveCancel(cause)

		// THE BACKSTOP.  Cancelling the root is not the same as halting, and the difference is not
		// theoretical: on 2026-08-25 this node sat wedged for 4h11m on ONE block after the cancel
		// fired, with a healthy enclave and nothing in the log.  Three of thirty-six stalls in that
		// log ended that way -- roughly one in twelve.
		//
		// The halt is REACTIVE: haltOnEnclaveFailure returns early on err == nil, so it only runs
		// if a blocked call actually unblocks with an error.  That requires the goroutine to be
		// sitting on a context descended from enclaveAlive.  Every exec path is supposed to be --
		// enclaveExecContext derives from it, and EnclaveAliveContext exists so dsvs's duplicate
		// tier does too -- but "supposed to be" is an invariant across many call sites, and a single
		// path that missed it turns a declared-dead enclave into a silent hang forever.
		//
		// So: having declared the enclave dead, do not WAIT to find out whether the cancellation
		// reached anything -- make it reach everything, immediately, by closing the transport too.
		// The cancel is irreversible (context.WithCancelCause cannot be un-cancelled), so every
		// future enclaveExecContext is born cancelled and this node can never execute another
		// block.  It is already unrecoverable at this point; the only question is whether it says
		// so, and closing the transport is what makes it say so reliably.
		//
		// ONE MECHANISM, NOT TWO.  There is no longer a "normal" and an "abnormal" path here:
		// every declared-dead enclave is handled the same way, and the only thing that varies is
		// whether a call existed to halt.
		//
		// The cancel above records WHY and shuts the one-way door.  On its own it is opt-in per
		// call site -- the blocked goroutine must be sitting on a context descended from
		// enclaveAlive -- and a single call site that missed that invariant hangs forever
		// (2026-08-25: wedged 4h11m on ONE block, healthy enclave, nothing in the log).
		//
		// Closing the transport is not opt-in.  gRPC fails every RPC on a closed ClientConn, so
		// the stuck call unblocks whatever context it holds, returns an error, and reaches
		// haltOnEnclaveFailure -- which reports the CAUSE recorded above rather than the bare
		// "connection closed" it would otherwise see.  That is why the cancel comes first and the
		// close immediately after: the cancel supplies the reason, the close supplies the
		// guarantee.
		//
		// This does not touch the enclave process.  Only our client side goes; the enclave keeps
		// running and keeps serving its socket, so a restarted node still ADOPTS it warm.
		closeEnclaveTransport(logger)

		// The halt is reactive, so give the unblocked call a moment to unwind into the panic and
		// set the flag.
		time.Sleep(enclaveHaltBackstop)

		// THIS NODE DOES NOT EXIT, and that is deliberate.  It used to, so a supervisor would
		// restart it -- but the restart destroys the evidence.  Twice on 2026-08-29 systemd
		// restarted this node within 5s of the exit, each time erasing the state that would have
		// explained WHY the halt never ran, and each time breaking the suite mid-run.  A restart
		// is recovery of availability at the cost of the only forensics there are.
		//
		// A halted node is not invisible unless your monitoring was already wrong: this project's
		// own rule is that "processes being up is not health -- the height must be seen to
		// ADVANCE".  A stopped height is exactly what this state produces.
		//
		// The operator restarts it when they have what they need.  What they need is the line
		// below, which says WHICH of four states this is -- the distinction the single
		// enclaveHaltAnnounced bit could never make on its own.
		inFlightNow := enclaveCallsInFlight.Load()
		unblocked := enclaveCallsFailedPostCancel.Load() - failedBefore

		switch {
		case enclaveHaltAnnounced.Load():
			// The common, healthy-mechanism case: a call was reached and halted for it.
			c.LoggerError(logger, fmt.Sprintf(
				"enclave dead (%v). in-flight at cancel: %d, unblocked with errors: %d, "+
					"halt announced: YES -- consensus is stopped and this process stays up for "+
					"inspection.  Restart it when you are done; startup reconciliation recovers.",
				cause, inFlightAtCancel, unblocked))

		case inFlightAtCancel == 0:
			// Genuinely idle when the enclave died.  Nothing could panic on its behalf, so there
			// is no named halt to be had -- which is why this line has to say so out loud.  The
			// root is cancelled and irreversible, so the next block cannot execute either.
			c.LoggerError(logger, fmt.Sprintf(
				"enclave dead (%v). in-flight at cancel: 0, halt announced: no -- the node was "+
					"IDLE, so there was no call to halt and consensus stopped without a block.  "+
					"This node will not produce again; restart it when you are ready.", cause))

		case unblocked > 0:
			// The calls DID come back with errors, and still nothing halted.  That is not a wedge:
			// it is a call site that swallowed the error instead of calling haltOnEnclaveFailure.
			// Previously indistinguishable from "idle", and so never once diagnosed.
			c.LoggerError(logger, fmt.Sprintf(
				"enclave dead (%v). in-flight at cancel: %d, unblocked with errors: %d, "+
					"halt announced: NO -- the calls returned but NOTHING HALTED FOR THEM.  A call "+
					"site is swallowing the error instead of calling haltOnEnclaveFailure; find it "+
					"with the %d method(s) still counted below.",
				cause, inFlightAtCancel, unblocked, inFlightNow))

		default:
			// Still stuck after both the cancellation and the transport close.  This is the real
			// wedge -- 2026-08-25, 4h11m on ONE block with a healthy enclave and nothing in the
			// log.  It is the case the old message actively misreported as "no in-flight call".
			c.LoggerError(logger, fmt.Sprintf(
				"enclave dead (%v). in-flight at cancel: %d, unblocked with errors: 0, still in "+
					"flight: %d, halt announced: NO -- WEDGED: neither the cancellation nor the "+
					"transport close reached those calls.  Capture goroutine state before "+
					"restarting; this is the case that has no other evidence.",
				cause, inFlightAtCancel, inFlightNow))
		}
		return
	}
}
