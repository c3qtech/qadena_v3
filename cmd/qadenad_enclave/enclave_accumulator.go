package main

// Per-prefix store accumulators, maintained as rows are written.
//
// RUNS ALONGSIDE THE SCAN, NOT INSTEAD OF IT.  GetStoreHash keeps computing StoreHashByStoreKey and
// keeps returning it; the accumulator is compared against that result and disagreement is reported.
// Until the shadow has been quiet for a long time on a real chain, the scan is the truth and this
// is a claim about the scan.
//
// That is deliberate.  An accumulator is a MAINTAINED INVARIANT, correct only while every write
// path updates it, and this repository has been bitten twice by exactly that shape: the iavl fast
// index (derived, absent from snapshots, silently empty) and CredentialPCXY (derived, rebuilt
// lossily, 972 rows short).  A drifted accumulator would be worse than either, because its output
// is a hash -- nothing about it looks wrong.  The shadow comparison is what makes it safe to build.
//
// STORED INSIDE THE VERSIONED TREE, like preparedHeight and unlike confirmedHeight, so that a
// rollback rewinds the accumulators along with the rows they describe.  An accumulator in raw
// MetaDB would survive a rollback and then describe state that no longer exists.

import (
	"context"
	"fmt"

	"cosmossdk.io/store/prefix"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"
	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

// accumulatorLog formats the three things any accumulator line has to carry to be worth reading:
// which store, how many rows the value covers, and the value itself.  The row count is what makes a
// hex digest actionable -- two nodes disagreeing at the same count is a content difference, at
// different counts it is a missing or extra row.
func accumulatorLog(pfx string, rows int, acc c.StoreAccumulator) string {
	return fmt.Sprintf("key=%s rows=%d acc=%s", pfx, rows, c.AccumulatorHex(acc))
}

// EnclaveStoreAccumulatorKeyPrefix holds one row per accumulated prefix, keyed by that prefix.
//
// DELIBERATELY NOT ONE OF THE ACCUMULATED PREFIXES, or the accumulator would be hashing itself:
// writing it would change the table it summarises, which would change it again.
const EnclaveStoreAccumulatorKeyPrefix = "Enclave/StoreAccumulator/value/"

func (s *qadenaServer) accumulatorStore() prefix.Store {
	return prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(EnclaveStoreAccumulatorKeyPrefix))
}

// loadAccumulator returns the stored value, and whether one was stored at all.
//
// ABSENT IS NOT ZERO.  An empty table accumulates to zero legitimately, so "nothing stored" has to
// stay distinguishable from "stored zero" -- a fresh enclave, a restored snapshot and a
// just-truncated table are three different situations and only one of them is a real zero.
func (s *qadenaServer) loadAccumulator(pfx string) (c.StoreAccumulator, bool) {
	return c.ParseStoreAccumulator(s.accumulatorStore().Get([]byte(pfx)))
}

func (s *qadenaServer) saveAccumulator(pfx string, acc c.StoreAccumulator) {
	s.accumulatorStore().Set([]byte(pfx), c.StoreAccumulatorBytes(acc))
}

// accumulateWrite folds one row change into the prefix's accumulator.
//
// Call it BEFORE the store write, because it needs the row's previous value: an overwrite has to
// subtract the old contribution before adding the new one, and after the write the old value is
// gone.  Passing newValue nil means a delete.
//
// A NO-OP WHEN NOTHING IS STORED YET.  Seeding writes thousands of rows into a fresh enclave; there
// is no point maintaining an accumulator that does not exist, and doing so would produce a value
// covering only the rows seen since the process started.  ensureAccumulator builds it once, by
// scanning, at the point it is first needed.
func (s *qadenaServer) accumulateWrite(pfx string, key []byte, newValue []byte) {
	acc, ok := s.loadAccumulator(pfx)
	if !ok {
		return // not established yet; the shadow comparison will schedule a rebuild
	}

	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(pfx))
	if old := store.Get(key); old != nil {
		acc = c.AccumulatorSub(acc, key, old)
	}
	if newValue != nil {
		acc = c.AccumulatorAdd(acc, key, newValue)
	}
	s.saveAccumulator(pfx, acc)
}

// ensureAccumulator establishes the accumulator for a prefix by scanning, if it has none.
//
// This is the recovery path for every case where rows arrived without passing through the setters
// -- a fresh enclave, a snapshot restore, a bulk seed -- which is the same class of gap that left
// the iavl fast index empty.  Recomputing from the data itself cannot drift; the only cost is one
// scan, once.
func (s *qadenaServer) ensureAccumulator(pfx string) c.StoreAccumulator {
	if acc, ok := s.loadAccumulator(pfx); ok {
		return acc
	}
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(pfx))
	acc, rows := c.AccumulatorFromPrefixStore(store)
	s.saveAccumulator(pfx, acc)
	c.LoggerInfo(logger, "ACCUMULATOR established "+accumulatorLog(pfx, rows, acc))
	return acc
}

// GetStoreAccumulators is the accumulator seam: GetStoreHash's equivalent for the maintained
// values, and DELIBERATELY A WRITING RPC where GetStoreHash must not be.  The read-only constraint
// that forced establishment into a flag-then-next-write dance belongs to GetStoreHash specifically
// (its commitCache history), not to the seam: this handler establishes any missing accumulator
// before answering, so "absent" is impossible in a current-height reply and both sides of a
// comparison exist at the moment of exchange.
//
// A NON-ZERO HEIGHT is a read of the versioned store as of that height, WITHOUT establishing --
// history cannot be written.  Historical entries may honestly be absent: an accumulator did not
// exist before the block that established it, and absent != zero (a zero would read as "empty
// store" and fail every non-empty comparison).
func (s *qadenaServer) GetStoreAccumulators(ctx context.Context, in *types.MsgGetStoreAccumulators) (*types.GetStoreAccumulatorsReply, error) {
	want := map[string]bool{}
	for _, k := range in.GetKeys() {
		want[k] = true
	}

	reply := &types.GetStoreAccumulatorsReply{}

	err := s.withHeightPinned(in.GetHeight(), func(view *qadenaServer) error {
		for _, pfx := range storeHashKeys {
			if len(want) > 0 && !want[pfx] {
				continue
			}

			entry := &types.StoreAccumulatorEntry{Key: pfx, Rows: -1}

			if in.GetHeight() > 0 {
				// Historical: read-only, absent stays absent.
				if acc, ok := view.loadAccumulator(pfx); ok {
					entry.Acc, entry.Present = acc[:], true
				}
			} else {
				// Current: establish-then-answer -- but ANSWER FROM THE COMMITTED ROW when one
				// exists, exactly as compareAccumulatorToScan reads, because GetStoreHash hashes
				// ServerCtx.  The seam compares this reply against those hashes, and the two must
				// sample the SAME commit point: answering from CacheCtx made the accumulator see
				// freshly seeded rows a block before the scan hash did, and the side-by-side
				// check reported the two mechanisms disagreeing when they were merely reading
				// different clocks (observed live: accAgree=true scanAgree=false on exactly the
				// three seeded stores, first boot, 2026-08-16).
				stored := prefix.NewStore(s.ServerCtx.KVStore(s.StoreKey), types.KeyPrefix(EnclaveStoreAccumulatorKeyPrefix))
				if acc, ok := c.ParseStoreAccumulator(stored.Get([]byte(pfx))); ok {
					entry.Acc, entry.Present = acc[:], true
				} else {
					// No committed accumulator row yet.  ANSWER THE ACCUMULATOR OF THE COMMITTED
					// CONTENT -- a ServerCtx scan, the same store GetStoreHash hashes -- NOT the
					// cache establishment value.  The distinction is not pedantry: at first boot
					// the enclave's own startup has already written its identity, interval keys
					// and pubkeys into the CACHE, so a cache-derived answer describes rows the
					// committed clock has never seen, and the seam reported the two mechanisms
					// disagreeing when each was honestly reporting a different commit point
					// (observed twice, 2026-08-16/17, accAgree=true scanAgree=false on exactly
					// the enclave's self-written stores).  This scan runs only in the
					// never-committed window; it is the same cost GetStoreHash pays every call.
					committed, rows := c.AccumulatorFromPrefixStore(
						prefix.NewStore(s.ServerCtx.KVStore(s.StoreKey), types.KeyPrefix(pfx)))
					entry.Acc, entry.Present, entry.Rows = committed[:], true, int64(rows)

					// Maintenance establishment is a SEPARATE concern and keeps its cache
					// semantics: the maintained value must cover the cache's rows or the first
					// commit would immediately falsify it.  It just must not leak into the reply.
					if _, ok := s.loadAccumulator(pfx); !ok {
						fresh, n := c.AccumulatorFromPrefixStore(
							prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(pfx)))
						s.saveAccumulator(pfx, fresh)
						c.LoggerInfo(logger, "ACCUMULATOR established "+accumulatorLog(pfx, n, fresh))
					}
				}
			}

			reply.Accumulators = append(reply.Accumulators, entry)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return reply, nil
}

// maintainAccumulators establishes anything missing and rebuilds anything flagged, for every
// mirrored store, once per block.
//
// THIS IS WHAT MAKES THE ACCUMULATORS RELIABLE.  Establishment used to piggyback on the next
// ordinary write to a store, which meant a store nobody writes to never got one: EnclaveIdentity,
// PioneerJar and JarRegulator can go an entire run without a single write, so the shadow covered
// exactly the stores that needed watching least.  Hanging it off EndBlock instead makes coverage a
// function of the block height rather than of traffic.
//
// Called from EndBlock BEFORE commitCache, so these writes land in the same version as the block's
// own -- the same reason the prepared-height stamp goes through the cache.  A rollback then rewinds
// the accumulators together with the rows they describe.
//
// The steady-state cost is one store Get per mirrored store per block.  A scan happens only when a
// store has no accumulator or has just been flagged, which is once per store in the normal case.
func (s *qadenaServer) maintainAccumulators() {
	for _, pfx := range storeHashKeys {
		if _, ok := s.loadAccumulator(pfx); !ok {
			s.ensureAccumulator(pfx)
		}
	}
}

// accumulatorAuditInterval is how often each side re-derives every accumulator from its own
// store's rows and compares it to the maintained value.  The audit is the one scan-shaped thing
// that survives the phase-out, because a maintained invariant can never self-certify: an unhooked
// write path leaves BOTH sides' accumulators stale in unison, so every cross-boundary comparison
// keeps passing while the summaries drift from the data -- the exact rot that emptied the iavl
// fast index and shorted CredentialPCXY.  Only re-deriving from the data catches it.
//
// The same cadence the old debug-gated hash display used; at 1/25th frequency the scans cost
// almost nothing.
const accumulatorAuditInterval = 25

// auditAccumulators recomputes every mirrored store's accumulator from the block-end data and
// compares it to the maintained row -- same store, same context, same instant, same arithmetic,
// so there are no clocks to misalign and a mismatch means the invariant is genuinely violated:
// an unhooked write path, or data corruption.
//
// A MISMATCH HALTS, IT DOES NOT REPAIR.  Repairing would either mask a code defect forever (the
// unhooked path keeps corrupting the summary and the node keeps quietly patching it) or bless
// corrupted data as the new truth.  The error returns through EndBlock into the chain's
// haltOnEnclaveFailure -- the loud, named, recoverable stop.
func (s *qadenaServer) auditAccumulators(height int64) error {
	if height%accumulatorAuditInterval != 0 {
		return nil
	}
	for _, pfx := range storeHashKeys {
		maintained, ok := s.loadAccumulator(pfx)
		if !ok {
			// maintainAccumulators runs first; absent here is a call-order bug, not a violation
			return fmt.Errorf("accumulator audit: no maintained value for %s after the maintain pass", pfx)
		}
		store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(pfx))
		scanned, rows := c.AccumulatorFromPrefixStore(store)
		if maintained != scanned {
			return fmt.Errorf("accumulator audit FAILED for %s at height %d: maintained=%s scanned=%s rows=%d -- "+
				"an unhooked write path or corrupted data; halting rather than repairing, because repair "+
				"would either mask the defect or bless the corruption",
				pfx, height, c.AccumulatorHex(maintained), c.AccumulatorHex(scanned), rows)
		}
	}
	c.LoggerDebug(logger, fmt.Sprintf("accumulator audit clean at height %d (%d stores)", height, len(storeHashKeys)))
	return nil
}

// collectAccumulatorEntries snapshots every mirrored store's maintained accumulator for the
// EndBlock reply.  Called after maintainAccumulators and before the commit, so every store has a
// value and the values are exactly what this block commits.  One Get per store; no scans.
func (s *qadenaServer) collectAccumulatorEntries() []*types.StoreAccumulatorEntry {
	out := make([]*types.StoreAccumulatorEntry, 0, len(storeHashKeys))
	for _, pfx := range storeHashKeys {
		acc, ok := s.loadAccumulator(pfx)
		if !ok {
			// Cannot happen after maintainAccumulators; reported rather than invented as zero.
			out = append(out, &types.StoreAccumulatorEntry{Key: pfx, Rows: -1})
			continue
		}
		out = append(out, &types.StoreAccumulatorEntry{Key: pfx, Acc: acc[:], Rows: -1, Present: true})
	}
	return out
}
