package keeper

// The chain half of the shadow accumulators.  The enclave half is cmd/qadenad_enclave/
// enclave_accumulator.go, and both fold rows with the SAME helper in x/qadena/common -- one
// implementation, so the two sides cannot drift in formulation while appearing to agree.
//
// RUNS ALONGSIDE THE SCAN.  StoreHashByKVStoreService keeps scanning and keeps being the answer;
// this only reports whether the maintained value agrees.  See the enclave file for why an
// accumulator is treated as a claim rather than a fact until it has been quiet for a long time.

import (
	"context"
	"fmt"
	"sort"

	"cosmossdk.io/store/prefix"
	"github.com/cosmos/cosmos-sdk/runtime"
	sdk "github.com/cosmos/cosmos-sdk/types"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"
	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

// StoreAccumulatorKeyPrefix holds one row per accumulated prefix, keyed by that prefix.
//
// NOT one of the accumulated prefixes, or writing it would change the table it summarises.
const StoreAccumulatorKeyPrefix = "StoreAccumulator/value/"

func (k Keeper) accumulatorStore(ctx context.Context) prefix.Store {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	return prefix.NewStore(storeAdapter, types.KeyPrefix(StoreAccumulatorKeyPrefix))
}

func (k Keeper) tableStore(ctx context.Context, pfx string) prefix.Store {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	return prefix.NewStore(storeAdapter, types.KeyPrefix(pfx))
}

// LoadStoreAccumulator returns the stored value and whether one exists.  Absent is not zero: an
// empty table accumulates to zero legitimately, and a missing accumulator means "unknown".
func (k Keeper) LoadStoreAccumulator(ctx context.Context, pfx string) (c.StoreAccumulator, bool) {
	return c.ParseStoreAccumulator(k.accumulatorStore(ctx).Get([]byte(pfx)))
}

func (k Keeper) saveStoreAccumulator(ctx context.Context, pfx string, acc c.StoreAccumulator) {
	k.accumulatorStore(ctx).Set([]byte(pfx), c.StoreAccumulatorBytes(acc))
}

// AccumulateWrite folds one row change in.  CALL BEFORE THE STORE WRITE: an overwrite has to
// subtract the row's previous value, and after the write that value is gone.  newValue nil = delete.
//
// A no-op until the accumulator has been established, because genesis and the mirror push write in
// bulk and a value covering only "rows seen since startup" would be worse than none.
func (k Keeper) AccumulateWrite(ctx context.Context, pfx string, key []byte, newValue []byte) {
	c.AccumulateRowWrite(k.accumulatorStore(ctx), k.tableStore(ctx, pfx), pfx, key, newValue)
}

// EnsureStoreAccumulator establishes a prefix's accumulator by scanning, if it has none.  This is
// the path for rows that arrived without passing through a setter -- genesis, a state-sync restore,
// a bulk seed -- which is the same gap that left the iavl fast index silently empty.
func (k Keeper) EnsureStoreAccumulator(ctx context.Context, pfx string) c.StoreAccumulator {
	if acc, ok := k.LoadStoreAccumulator(ctx, pfx); ok {
		return acc
	}
	acc, rows := c.AccumulatorFromPrefixStore(k.tableStore(ctx, pfx))
	k.saveStoreAccumulator(ctx, pfx, acc)
	if sdkctx, ok := ctx.(sdk.Context); ok {
		c.ContextInfo(sdkctx, "ACCUMULATOR established "+accumulatorLog(pfx, rows, acc))
	}
	return acc
}

// accumulatorLog matches the enclave's format deliberately (cmd/qadenad_enclave/
// enclave_accumulator.go).  The whole purpose of these two accumulators is to be COMPARED, so their
// log lines have to be greppable and diffable side by side -- same store, same row count, same
// digest, or the two halves disagree.
func accumulatorLog(pfx string, rows int, acc c.StoreAccumulator) string {
	return fmt.Sprintf("key=%s rows=%d acc=%s", pfx, rows, c.AccumulatorHex(acc))
}

// maintainStoreAccumulators establishes any missing accumulator, for every mirrored store, once
// per block -- the chain-side twin of the enclave's maintainAccumulators, called from
// EnclaveEndBlock.  After the first block each pass costs one store Get per prefix.
//
// THIS IS THE ACTIVATION POINT, and it is CONSENSUS-VISIBLE: the rows it writes live in the
// qadena module store, which feeds the app hash.  The arithmetic is deterministic -- every node
// running this code computes byte-identical rows from byte-identical writes -- so upgraded nodes
// agree with each other, but they disagree with un-upgraded ones from the first block after the
// swap.  All nodes of a chain must cross this change together.
//
// dsvs's AuthorizedSignatory is deliberately absent: that store lives in the dsvs module's own
// store space, which this keeper cannot reach; the dsvs keeper establishes it from its own
// per-block hook.
func (k Keeper) maintainStoreAccumulators(sdkctx sdk.Context) {
	// Sorted, not ranged: map order varies per process, and while the WRITE-SET is identical
	// either way (commits sort by key), nobody should have to prove that to review this.
	prefixes := make([]string, 0, len(mirroredStores))
	for pfx := range mirroredStores {
		prefixes = append(prefixes, pfx)
	}
	sort.Strings(prefixes)
	for _, pfx := range prefixes {
		k.EnsureStoreAccumulator(sdkctx, pfx)
	}
}

// comparePerBlockAccumulators is the EVERY-BLOCK content-agreement check, fed by the accumulators
// the enclave returns on its EndBlock reply (captured there after its maintain pass, before its
// commit -- the same block-end clock this keeper's maintainStoreAccumulators, which runs just
// before the rpc, gives the chain's rows).  Ten 33-byte comparisons per block; no scans anywhere.
//
// A DIVERGENCE LOGS AT ERROR RATHER THAN HALTING, deliberately, for now: the seam's side-by-side
// period caught two subtle clock bugs in its first day, and per-block halting graduates only
// through backlog item 46's evidence gate, exactly like every other promotion in this design.
// (Halting here would be node-local and fork-safe -- halt-or-proceed, never divergent state -- so
// the graduation is about confidence, not safety.)
//
// An EMPTY entries list is an old enclave that predates the field; the check simply does not run,
// which keeps the chain compatible across the upgrade window.  dsvs's AuthorizedSignatory arrives
// in the reply but lives in that module's store space, unreachable from this keeper -- it stays
// covered by dsvs's own scan-moment compares.
func (k Keeper) comparePerBlockAccumulators(sdkctx sdk.Context, entries []*types.StoreAccumulatorEntry) {
	if len(entries) == 0 {
		return
	}
	agree := 0
	for _, e := range entries {
		if !mirroredStores[e.GetKey()] {
			continue
		}
		if !e.GetPresent() {
			c.ContextError(sdkctx, "Qadena: PER-BLOCK ACC missing on the enclave for key="+e.GetKey()+
				" -- cannot happen after its maintain pass; investigate")
			continue
		}
		chainAcc, ok := k.LoadStoreAccumulator(sdkctx, e.GetKey())
		if !ok {
			c.ContextError(sdkctx, "Qadena: PER-BLOCK ACC missing on the chain for key="+e.GetKey()+
				" -- cannot happen after maintainStoreAccumulators; call order bug")
			continue
		}
		if string(chainAcc[:]) != string(e.GetAcc()) {
			c.ContextError(sdkctx, fmt.Sprintf(
				"Qadena: PER-BLOCK ACC DIVERGENCE key=%s height=%d chain=%s enclave=%x -- "+
					"chain and enclave committed different content for the same block",
				e.GetKey(), sdkctx.BlockHeight(), c.AccumulatorHex(chainAcc), e.GetAcc()))
			continue
		}
		agree++
	}
	c.ContextDebug(sdkctx, fmt.Sprintf("Qadena: per-block accumulators agree on %d store(s) at height %d", agree, sdkctx.BlockHeight()))
}

// accumulatorAuditInterval mirrors the enclave's: every Nth block each side re-derives its
// accumulators from its own rows.  See the enclave's constant for the full rationale.
const accumulatorAuditInterval = 25

// auditStoreAccumulators is the chain half of the honesty audit.  Panics on mismatch -- see the
// call site in EnclaveEndBlock for why halting is correct and what chain-wide means.
func (k Keeper) auditStoreAccumulators(sdkctx sdk.Context) {
	if sdkctx.BlockHeight()%accumulatorAuditInterval != 0 {
		return
	}
	prefixes := make([]string, 0, len(mirroredStores))
	for pfx := range mirroredStores {
		prefixes = append(prefixes, pfx)
	}
	sort.Strings(prefixes)
	for _, pfx := range prefixes {
		maintained, ok := k.LoadStoreAccumulator(sdkctx, pfx)
		if !ok {
			panic(fmt.Sprintf("qadena: accumulator audit: no maintained value for %s after the maintain pass -- call order bug", pfx))
		}
		scanned, rows := c.AccumulatorFromPrefixStore(k.tableStore(sdkctx, pfx))
		if maintained != scanned {
			panic(fmt.Sprintf(
				"qadena: accumulator audit FAILED for %s at height %d: maintained=%s scanned=%s rows=%d -- "+
					"an unhooked write path or corrupted data; halting rather than repairing, because repair "+
					"would either mask the defect or bless the corruption",
				pfx, sdkctx.BlockHeight(), c.AccumulatorHex(maintained), c.AccumulatorHex(scanned), rows))
		}
	}
	c.ContextDebug(sdkctx, fmt.Sprintf("Qadena: accumulator audit clean at height %d (%d stores)", sdkctx.BlockHeight(), len(prefixes)))
}
