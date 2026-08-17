package keeper

// Shims for the external test package (keeper_test), which cannot import testutil/keeper from an
// in-package test file without an import cycle.  Everything here is test-only surface over
// unexported machinery -- no behaviour.

import (
	sdk "github.com/cosmos/cosmos-sdk/types"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"
)

// EnclaveSynchronizeStoresForTest exposes the startup mirror comparison, the thing the injected
// divergence tests exercise.
func (k Keeper) EnclaveSynchronizeStoresForTest(sdkctx sdk.Context) error {
	return k.enclaveSynchronizeStores(sdkctx)
}

// StoreHashForTest computes the chain's own content hash for a mirrored prefix -- what a truthful
// enclave would report.  Exposed because the test cannot reach k.storeService.
func (k Keeper) StoreHashForTest(sdkctx sdk.Context, key string) string {
	return c.StoreHashByKVStoreService(sdkctx, k.storeService, key)
}

// SetEnclaveHeightsAgreedForTest drives the flag that separates "seeding a fresh enclave"
// (expected) from "stores diverged at an agreed height" (the alarm).  Callers must restore false.
func SetEnclaveHeightsAgreedForTest(v bool) { enclaveHeightsAgreedAtStartup = v }

// MaintainStoreAccumulatorsForTest exposes the per-block establishment pass.
func (k Keeper) MaintainStoreAccumulatorsForTest(sdkctx sdk.Context) {
	k.maintainStoreAccumulators(sdkctx)
}

// RawStoreSetForTest writes a row directly, bypassing every setter and hook -- the injection the
// unhooked-write tests need.
func (k Keeper) RawStoreSetForTest(sdkctx sdk.Context, pfx string, key, value []byte) {
	k.tableStore(sdkctx, pfx).Set(key, value)
}

// MirroredStorePrefixesForTest lists the prefixes maintainStoreAccumulators covers.
func MirroredStorePrefixesForTest() []string {
	out := make([]string, 0, len(mirroredStores))
	for pfx := range mirroredStores {
		out = append(out, pfx)
	}
	return out
}

// AuditStoreAccumulatorsForTest exposes the honesty audit (panics on violation, exactly as live).
func (k Keeper) AuditStoreAccumulatorsForTest(sdkctx sdk.Context) { k.auditStoreAccumulators(sdkctx) }
