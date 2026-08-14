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
	"sync/atomic"
	"time"

	sdk "github.com/cosmos/cosmos-sdk/types"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"
)

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
func enclaveExecContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
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
