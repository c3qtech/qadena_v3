package keeper_test

// The chain-side accumulator ACTIVATION, tested with the same three properties the enclave's
// suite pins (cmd/qadenad_enclave/enclave_accumulator_test.go), because the two halves are the
// same design in two trust domains and must not drift in behaviour either:
//
//  1. the per-block pass establishes every mirrored store's accumulator, without any traffic;
//  2. once established, the ordinary setters maintain it exactly -- verified by the shadow scan;
//  3. a write that bypasses the hooks is DETECTED, and then repaired.

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"cosmossdk.io/log"
	"github.com/stretchr/testify/require"

	keepertest "github.com/c3qtech/qadena_v3/testutil/keeper"
	"github.com/c3qtech/qadena_v3/x/qadena/keeper"
	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

func TestChainMaintainEstablishesEveryMirroredAccumulator(t *testing.T) {
	k, ctx := keepertest.QadenaKeeper(t)

	// Rows first, so establishment has real content to scan -- and rows that arrived WITHOUT the
	// hooks seeing them, which is exactly the genesis/state-sync shape establishment exists for.
	for i := 0; i < 5; i++ {
		k.SetWalletNoEnclave(ctx, types.Wallet{WalletID: fmt.Sprintf("est-%d", i)})
	}

	for _, pfx := range keeper.MirroredStorePrefixesForTest() {
		_, ok := k.LoadStoreAccumulator(ctx, pfx)
		require.False(t, ok, "nothing may exist before the first block's pass: "+pfx)
	}

	k.MaintainStoreAccumulatorsForTest(ctx)

	for _, pfx := range keeper.MirroredStorePrefixesForTest() {
		_, ok := k.LoadStoreAccumulator(ctx, pfx)
		require.True(t, ok, "the per-block pass must establish every mirrored store, traffic or not: "+pfx)
	}

	// And the established values must equal the data: the shadow compare repairs on mismatch and
	// logs MISMATCH at ERROR, so a clean log IS the assertion.
	var buf bytes.Buffer
	ctx2 := ctx.WithLogger(log.NewLogger(&buf))
	for _, pfx := range keeper.MirroredStorePrefixesForTest() {
		k.CompareStoreAccumulator(ctx2, pfx)
	}
	require.NotContains(t, buf.String(), "ACCUMULATOR MISMATCH",
		"an establishing scan must reproduce the data exactly")
}

func TestChainHooksMaintainExactlyAfterEstablishment(t *testing.T) {
	k, ctx := keepertest.QadenaKeeper(t)
	k.MaintainStoreAccumulatorsForTest(ctx)

	// Insert, overwrite, and a fresh key -- through the REAL setter, post-establishment, so every
	// change flows through the hook's subtract/add arithmetic.
	k.SetWalletNoEnclave(ctx, types.Wallet{WalletID: "w1"})
	k.SetWalletNoEnclave(ctx, types.Wallet{WalletID: "w1", HomePioneerID: "pioneer1"}) // overwrite
	k.SetWalletNoEnclave(ctx, types.Wallet{WalletID: "w2"})

	var buf bytes.Buffer
	k.CompareStoreAccumulator(ctx.WithLogger(log.NewLogger(&buf)), types.WalletKeyPrefix)
	require.NotContains(t, buf.String(), "ACCUMULATOR MISMATCH",
		"incremental maintenance must land exactly on the from-scratch scan -- the overwrite is "+
			"the classic miss (forgetting to subtract leaves both contributions in the sum forever)")
}

func TestChainUnhookedWriteIsDetectedThenRepaired(t *testing.T) {
	k, ctx := keepertest.QadenaKeeper(t)
	k.MaintainStoreAccumulatorsForTest(ctx)

	// The hazard: a row written past every setter, so no hook fires.  This is the write shape the
	// scan audit exists to catch for as long as the accumulator lives (backlog item 46).
	k.RawStoreSetForTest(ctx, types.WalletKeyPrefix, []byte("smuggled"), []byte("row"))

	var buf bytes.Buffer
	k.CompareStoreAccumulator(ctx.WithLogger(log.NewLogger(&buf)), types.WalletKeyPrefix)
	require.Contains(t, buf.String(), "ACCUMULATOR MISMATCH",
		"an unhooked write must be detected -- silence here means the shadow is dead")

	// The chain-side compare repairs immediately (it runs from block execution, where writing is
	// expected), so a second compare must be clean.
	var buf2 bytes.Buffer
	k.CompareStoreAccumulator(ctx.WithLogger(log.NewLogger(&buf2)), types.WalletKeyPrefix)
	if strings.Contains(buf2.String(), "ACCUMULATOR MISMATCH") {
		t.Fatalf("the first compare must have repaired the value; log:\n%s", buf2.String())
	}
}
