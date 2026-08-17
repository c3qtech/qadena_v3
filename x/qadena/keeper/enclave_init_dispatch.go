package keeper

// The BeginBlock-anchored replacement for delayed_init_enclave.sh + init_enclave.sh.
//
// init-enclave is not a chain Msg: the CLI sent MsgInitEnclave over the unix socket and the
// ENCLAVE broadcast a fee-paying tx back into this node's own mempool.  The deleted scripts
// therefore had to poll `qadenad status` from outside until the RPC answered, the node was caught
// up, and the height passed an empirically chosen 4 -- ~200 lines re-deriving state the node
// holds natively.
//
// Here the TRIGGER lives in the qadena module's BeginBlock, so it is predictable and
// height-anchored; the CALL is dispatched async, because the tx the enclave broadcasts can only
// be admitted and included in a LATER block than the one executing.
//
// THE GATE HAS TWO PARTS, and the second one was learned the hard way.
//
//  1. CHAIN STATE: the JarRegulator row for this node's jar id is absent -- the precise on-chain
//     fact init-enclave exists to create.
//  2. THE BLOCK IS LIVE, not history being replayed.
//
// Part 2 is not optional, and an earlier version of this file argued it was.  The claim was that a
// joiner never fires because "the jar row arrives with the history it replays".  That is false:
// a block-syncing joiner EXECUTES BLOCK 2, and at that point in history the row genuinely did not
// exist yet -- so the gate fired on a joiner whose enclave `sync-enclave` had already initialized
// minutes earlier.  Observed on a real two-node join; harmless only because the enclave's
// InitEnclave handler is idempotent and answered "already initialized".  The version of that story
// with teeth is a joiner whose enclave is NOT yet initialized (started before sync-enclave, or
// re-joining with wiped enclave state): it would initialize mid-replay and broadcast a SECOND
// registration -- a duplicate jar and regulator on a chain that already has one.
//
// "Live" is decided by the BLOCK'S OWN TIMESTAMP against the wall clock: a block being produced
// now is seconds old, a block being replayed is as old as the history.  Reading the wall clock is
// safe HERE for the same reason the trigger is safe at all -- it writes no state and changes
// nothing any node computes; it only decides whether THIS node sends a transaction.
//
// Consensus-safe: the trigger writes no state -- it only sends a tx, which every node then
// validates like any other.
//
// WHO ARMS IT: only the start command (cmd/qadenad/cmd), which is the only place with the client
// context, keyring, moniker and external address the dispatch needs.  Unarmed (every other
// command, and every unit test), this file is inert.

import (
	"sync"
	"time"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"
	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

const (
	// The height the gate opens.  Replaces the scripts' magic "wait for height 4", which was
	// empirical slack for the RPC and the pioneer account to be queryable; both exist by the
	// time block 2 executes.
	initEnclaveMinHeight = 2

	// If a dispatch ran and the jar row still has not appeared this many blocks later, dispatch
	// again -- covers a broadcast that was admitted and then dropped.  The enclave side is
	// idempotent, so a re-dispatch can never double-initialize.
	initEnclaveRedispatchBlocks = 25

	// How fresh a block must be for this node to treat it as LIVE rather than replayed history.
	// Generous by design: block times are a second or two apart, so anything within a couple of
	// minutes is unambiguously current, while replayed history is minutes-to-months old.  Being
	// too generous only means a joiner that is nearly caught up might fire -- and by then the jar
	// row it checks has already arrived, so the gate is closed anyway.
	initEnclaveLiveBlockWindow = 2 * time.Minute
)

var initEnclaveDispatch struct {
	mu          sync.Mutex
	jarID       string
	fn          func() error // set only by the start command; nil = inert
	inFlight    bool
	lastAttempt int64
	doneForGood bool
}

// enclaveInitialized asks the enclave whether it already holds sealed params.  Returns
// (initialized, pioneerID, known); known is false when the question could not be answered -- an
// enclave too old to have the RPC, or one that did not respond -- in which case the caller must
// fall back rather than treat silence as "no".
func (k Keeper) enclaveInitialized() (bool, string, bool) {
	if EnclaveGRPCClient == nil {
		return false, "", false
	}
	ctx, cancel := enclaveQueryContext()
	defer cancel()
	r, err := EnclaveGRPCClient.GetEnclaveStatus(ctx, &types.MsgGetEnclaveStatus{})
	if err != nil {
		if status.Code(err) == codes.Unimplemented {
			c.LoggerInfo(k.logger, "init-enclave: this enclave predates GetEnclaveStatus, so it cannot say whether it is initialized -- falling back to InitEnclave's own idempotence")
		} else {
			c.LoggerError(k.logger, "init-enclave: could not read enclave status:", err.Error())
		}
		return false, "", false
	}
	return r.GetInitialized(), r.GetPioneerID(), true
}

// ArmInitEnclaveDispatch installs the dispatch closure.  jarID doubles as the gate's key: the
// dispatch is considered complete exactly when a JarRegulator row exists under it.
func ArmInitEnclaveDispatch(jarID string, fn func() error) {
	initEnclaveDispatch.mu.Lock()
	defer initEnclaveDispatch.mu.Unlock()
	initEnclaveDispatch.jarID = jarID
	initEnclaveDispatch.fn = fn
}

// MaybeDispatchInitEnclave is called from the qadena module's BeginBlock, every block, and is a
// few store-free comparisons on every path except the handful of blocks on a fresh chain where
// it actually has work to do.
func (k Keeper) MaybeDispatchInitEnclave(ctx sdk.Context) {
	d := &initEnclaveDispatch
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.fn == nil || d.doneForGood || d.inFlight {
		return
	}
	height := ctx.BlockHeight()
	if height < initEnclaveMinHeight {
		return
	}
	// REPLAYED HISTORY IS NOT AN INVITATION TO INITIALIZE.  Checked before the store read because
	// it is the cheaper question and the one that disqualifies whole syncs at a time.
	if bt := ctx.BlockTime(); !bt.IsZero() && time.Since(bt) > initEnclaveLiveBlockWindow {
		return
	}
	if _, found := k.GetJarRegulator(ctx, d.jarID); found {
		// The on-chain fact exists; nothing to do, ever again.  This is the branch every block
		// on every initialized chain takes (after one store read; doneForGood makes the NEXT
		// blocks take the flag branch above instead).
		d.doneForGood = true
		return
	}
	if d.lastAttempt != 0 && height < d.lastAttempt+initEnclaveRedispatchBlocks {
		return
	}

	// THE FINAL AUTHORITY, asked only now -- once every cheaper gate has already said "this looks
	// like a chain that needs initializing".  Every check above is a proxy; this is the fact.  It
	// is also the one answer that does not rewind during replay: the enclave's sealed params are
	// the same at replay height 2 as at live height 5000, which is exactly what chain state is not.
	//
	// An enclave predating this RPC answers Unimplemented; that is "cannot tell", not "no", so we
	// fall through to dispatching and rely on InitEnclave's own idempotence -- the behaviour before
	// this call existed.  Same shape as rollback.go's handling of an older enclave.
	initialized, pioneerID, statusKnown := k.enclaveInitialized()
	if statusKnown && initialized {
		c.LoggerInfo(k.logger, "init-enclave: the enclave reports it is already initialized as", pioneerID,
			"-- not initializing (this is the normal answer on a joiner, whose enclave sync-enclave set up before the node started)")
		d.doneForGood = true
		return
	}

	d.lastAttempt = height
	d.inFlight = true

	c.LoggerInfo(k.logger, "init-enclave: no JarRegulator on chain -- dispatching enclave initialization (trigger height", height, ")")
	fn := d.fn
	logger := k.logger
	// Captured for the success message: whether the enclave was able to tell us, a moment ago,
	// that it holds nothing.  When it could, the outcome below is not ambiguous.
	confirmedUninitialized := statusKnown
	go func() {
		err := fn()
		d.mu.Lock()
		d.inFlight = false
		d.mu.Unlock()
		if err != nil {
			// Not fatal: the gate re-arms initEnclaveRedispatchBlocks later.  The scripts'
			// response to this (kill the whole node) guarded a half-up state that cannot occur
			// now that init runs inside the node.
			c.LoggerError(logger, "init-enclave dispatch failed (will retry in", initEnclaveRedispatchBlocks, "blocks):", err.Error())
			return
		}
		// SAY ONLY WHAT WE KNOW, which now depends on whether the enclave could answer.
		//
		// InitEnclaveReply is a single bool meaning "accepted", identical for "I initialized now"
		// and "I short-circuited on already-initialized" (enclave.go:1624).  On its own that makes
		// any claim about a broadcast unfalsifiable -- an earlier version asserted "the enclave has
		// broadcast its registration; the JarRegulator row should appear within a few blocks", and
		// a joiner duly printed it while broadcasting nothing, pointing whoever read it at a row
		// that was never coming.
		//
		// But we asked GetEnclaveStatus moments ago.  When it answered, we know the enclave held
		// nothing, so the ambiguity is gone and the stronger sentence is the true one.  When it
		// could not answer (an older enclave), the hedge is still the honest form.
		if confirmedUninitialized {
			c.LoggerInfo(logger, "init-enclave: the enclave was uninitialized and has now broadcast its registration -- the JarRegulator row should appear within a few blocks")
		} else {
			c.LoggerInfo(logger, "init-enclave: the enclave accepted the request; this enclave cannot report its status, so it either initialized now or was already initialized")
		}
	}()
}
