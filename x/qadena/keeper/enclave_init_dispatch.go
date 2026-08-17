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
// THE GATE IS CHAIN STATE, not RPC polling: fire only when the JarRegulator row for this node's
// jar id is absent from the store -- the precise on-chain fact init-enclave exists to create.
// That one predicate covers every case the scripts special-cased:
//   - first pioneer, fresh chain: row absent at height 2 -> fire.  This is the ONLY case that
//     needs it.
//   - joiners: their enclave was initialized by `enclave sync-enclave` during promotion
//     (add_full_node.sh), and the jar row arrives WITH the history they replay -> never fires.
//     (Belt and braces: the enclave's InitEnclave handler is idempotent anyway.)
//   - any node replaying its own history: same.
// Consensus-safe: the trigger writes no state -- it only sends a tx, which every node then
// validates like any other.
//
// WHO ARMS IT: only the start command (cmd/qadenad/cmd), which is the only place with the client
// context, keyring, moniker and external address the dispatch needs.  Unarmed (every other
// command, and every unit test), this file is inert.

import (
	"sync"

	sdk "github.com/cosmos/cosmos-sdk/types"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"
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
)

var initEnclaveDispatch struct {
	mu           sync.Mutex
	jarID        string
	fn           func() error // set only by the start command; nil = inert
	inFlight     bool
	lastAttempt  int64
	doneForGood  bool
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
	d.lastAttempt = height
	d.inFlight = true

	c.LoggerInfo(k.logger, "init-enclave: no JarRegulator on chain -- dispatching enclave initialization (trigger height", height, ")")
	fn := d.fn
	logger := k.logger
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
		c.LoggerInfo(logger, "init-enclave dispatch succeeded -- the enclave has broadcast its registration; the JarRegulator row should appear within a few blocks")
	}()
}
