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
	// A shadow mismatch, or a table whose accumulator was never established, is repaired HERE --
	// the first write after the problem was noticed, which is a context where writing is expected.
	if s.takeAccumulatorReseed(pfx) {
		store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(pfx))
		rebuilt, rows := c.AccumulatorFromPrefixStore(store)
		s.saveAccumulator(pfx, rebuilt)
		// Info, not debug: this is rare (once per prefix in the normal case) and it is the moment
		// the accumulator starts making a claim.  A rebuild appearing repeatedly for the same store
		// means something keeps invalidating it, which is the signal worth catching early.
		c.LoggerInfo(logger, "ACCUMULATOR built by scan "+accumulatorLog(pfx, rows, rebuilt))
	}

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

// compareAccumulatorToScan is the shadow check.  READ-ONLY BY CONSTRUCTION.
//
// It is called from GetStoreHash, which must not write: that RPC used to commitCache() first and
// thereby promoted a partially executed transaction's writes into the store -- a write side effect
// on a read path, reachable from enclaveSynchronizeStores at startup.  So a mismatch here records
// an intent to re-seed rather than re-seeding, and the next ordinary write to that prefix does the
// work, where writing is already expected.
//
// It reads through ServerCtx, the same context GetStoreHash hashes, so the two describe the same
// committed state.  Comparing a CacheCtx accumulator against a ServerCtx scan would report
// uncommitted writes as drift.
//
// The log is at ERROR so it shows at info level, the way OUT-OF-SYNC already does: a mismatch means
// some write path is not maintaining the accumulator, which is the one thing that must be known
// before this is ever trusted for anything.
func (s *qadenaServer) compareAccumulatorToScan(pfx string) {
	store := prefix.NewStore(s.ServerCtx.KVStore(s.StoreKey), types.KeyPrefix(pfx))
	scanned, rows := c.AccumulatorFromPrefixStore(store)

	stored := prefix.NewStore(s.ServerCtx.KVStore(s.StoreKey), types.KeyPrefix(EnclaveStoreAccumulatorKeyPrefix))
	acc, ok := c.ParseStoreAccumulator(stored.Get([]byte(pfx)))
	if !ok {
		// Info rather than debug: on a fresh or restored enclave this is the FIRST thing the
		// accumulator says, and its absence from the log would make the silence ambiguous -- no
		// output could mean "agreeing quietly" or "never ran at all".
		//
		// ONLY WHEN THE FLAG ACTUALLY CHANGES, though.  A store is only established by a WRITE to
		// it, so a quiet store -- EnclaveIdentity, PioneerJar, JarRegulator go whole runs without
		// one -- stays absent indefinitely while GetStoreHash keeps asking.  Logging every
		// comparison would emit this on every EnclaveEndBlock that checks sync, forever.
		if s.markAccumulatorForReseed(pfx) { // never established, or lost to a restore
			c.LoggerInfo(logger, "ACCUMULATOR absent, will build on the next write to this store "+
				accumulatorLog(pfx, rows, scanned))
		}
		return
	}
	if acc != scanned {
		c.LoggerError(logger, "ACCUMULATOR MISMATCH key="+pfx+
			" rows="+fmt.Sprint(rows)+
			" maintained="+c.AccumulatorHex(acc)+
			" scanned="+c.AccumulatorHex(scanned)+
			" -- a write path is not maintaining it; re-seeding on the next write")
		s.markAccumulatorForReseed(pfx)
		return
	}

	// THE AGREEMENT IS THE POINT, so it is logged rather than left implicit.  Debug, because this
	// runs on every GetStoreHash and would otherwise drown the log -- but without it there is no
	// positive evidence the shadow ever ran, and "no mismatch" is indistinguishable from "no
	// comparison".  This is also the line to compare BETWEEN NODES: same store, same row count,
	// same digest means two enclaves hold identical content.
	c.LoggerDebug(logger, "ACCUMULATOR ok "+accumulatorLog(pfx, rows, acc))
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
		// Flagged wins: the value is present but known wrong, so re-reading it would be pointless.
		if s.takeAccumulatorReseed(pfx) {
			store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(pfx))
			rebuilt, rows := c.AccumulatorFromPrefixStore(store)
			s.saveAccumulator(pfx, rebuilt)
			c.LoggerInfo(logger, "ACCUMULATOR rebuilt at end of block "+accumulatorLog(pfx, rows, rebuilt))
			continue
		}
		if _, ok := s.loadAccumulator(pfx); !ok {
			s.ensureAccumulator(pfx)
		}
	}
}

// markAccumulatorForReseed records that a prefix's accumulator must be rebuilt from a scan.  Kept
// in memory rather than the store precisely because the caller is a read path; the flag costs
// nothing to lose on restart, since a fresh process re-derives it from the same comparison.
// Returns whether this call actually CHANGED the flag.  Callers use that to announce the condition
// once instead of on every comparison: a prefix can sit marked for a long time, because only a write
// to it clears the flag.
func (s *qadenaServer) markAccumulatorForReseed(pfx string) bool {
	s.accMu.Lock()
	defer s.accMu.Unlock()
	if s.accNeedsReseed == nil {
		s.accNeedsReseed = map[string]bool{}
	}
	if s.accNeedsReseed[pfx] {
		return false
	}
	s.accNeedsReseed[pfx] = true
	return true
}

func (s *qadenaServer) takeAccumulatorReseed(pfx string) bool {
	s.accMu.Lock()
	defer s.accMu.Unlock()
	if s.accNeedsReseed[pfx] {
		delete(s.accNeedsReseed, pfx)
		return true
	}
	return false
}
