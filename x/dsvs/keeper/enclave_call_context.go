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

import "context"

func enclaveExecContext() (context.Context, context.CancelFunc) {
	return context.WithCancel(context.Background())
}
