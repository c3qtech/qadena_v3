package keeper_test

import (
	"context"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// The keeper's Set* methods forward every write to the enclave over gRPC, and the test harness has
// no enclave behind it -- EnclaveGRPCClient is a nil package-level var assigned only from a live
// dial.  Every fixture below therefore dereferenced nil and took the whole package down with a
// SIGSEGV, which is why none of these tests have been running.
//
// The forward is skipped in CheckTx, so that flag is what makes them runnable.  It belongs here
// rather than as a nil guard inside the client: a guard that silently skipped the forward on a real
// validator would leave the enclave's copy of the store behind the chain's, which is precisely the
// divergence the GetStoreHash comparison exists to catch.
func testCtx(ctx context.Context) sdk.Context {
	return sdk.UnwrapSDKContext(ctx).WithIsCheckTx(true)
}
