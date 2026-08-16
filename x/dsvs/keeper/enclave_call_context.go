package keeper

// Execution-path context for calls into the enclave, mirroring the qadena keeper's helper of the
// same name. See x/qadena/keeper/enclave_call_context.go for the full reasoning -- in short, a
// wall-clock deadline on a call made during deterministic execution forks the node when the machine
// is loaded, which is what happened at height 34,025 on 2026-08-13.
//
// Both dsvs call sites (displayStoresSync, EnclaveSynchronizeStores) run from EnclaveBeginBlock, so
// both are execution path. There is no query-path variant here because dsvs has no query-path
// enclave call.
//
// This is duplicated rather than shared because the natural shared home, x/qadena/common, is
// imported by cmd/qadenad_enclave -- and changing that package's contents risks perturbing the
// enclave binary, whose measurement genesis records.
//
// DERIVED FROM THE QADENA KEEPER'S ALIVE-ROOT, not from context.Background().  The watchdog there
// cancels that root when the enclave has stopped serving anything; without inheriting it, a stopped
// enclave could leave the node blocked HERE, in dsvs's BeginBlock, where the cancellation would
// never reach -- the silent-hang failure mode surviving through a different door.  The import is
// acyclic: the qadena keeper does not import this package.
//
// dsvs's error handling is unchanged by this: its callers log and continue, they never halt.  The
// named halt still comes from the qadena keeper's EndBlock, which fails the same way at the same
// moment.

import (
	"context"

	qadenakeeper "github.com/c3qtech/qadena_v3/x/qadena/keeper"
)

func enclaveExecContext() (context.Context, context.CancelFunc) {
	return context.WithCancel(qadenakeeper.EnclaveAliveContext())
}
