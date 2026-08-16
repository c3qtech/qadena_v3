package common

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"math/big"

	"cosmossdk.io/store/prefix"
)

// An ORDER-INDEPENDENT, INCREMENTALLY MAINTAINABLE digest of a prefix store.
//
// WHY THIS EXISTS.  StoreHashByPrefixStore answers "what is in this table" by scanning all of it,
// and the enclave/chain comparison calls it for ten prefixes on both sides -- roughly 32,000 rows
// today, on every block where the outbox delivered anything.  That cost grows with the tables,
// which grow without bound.
//
// WHY A SUM RATHER THAN A HASH CHAIN.  A running sha256 over the iterator depends on the order rows
// arrive in, and the two sides do NOT write in the same order:
//
//   seeding      enclaveSynchronizeStores pushes GetAllWallet's output, which is sorted by KEY,
//                while the chain accumulated those same rows over thousands of blocks in TIME
//                order.  An order-dependent digest would differ immediately after every seed, with
//                byte-identical content.
//   rollback     rewinding the tree cannot rewind a hash chain; it would have to be replayed from
//                a checkpoint.  A sum stored in versioned state rolls back with everything else.
//
// Live traffic IS ordered identically on both sides -- deterministic transaction order, and the
// outbox is order-preserving -- so a chain would work MOST of the time.  That is precisely the
// wrong property for a divergence detector: the cases where the order differs are seeding, replay
// and recovery, which are the cases the detector exists for.  A false OUT-OF-SYNC after every seed
// teaches everyone to ignore it.
//
// So: acc = SUM over rows of H(row), mod 2^256.  Adding a row and removing it are inverses, order
// cannot matter, and an update is a subtract followed by an add.
//
// WHY LENGTH-PREFIXED.  Same reason hashEntries in the enclave's digest does it: without encoding
// the boundary, ("ab","c") and ("a","bc") collide, and a digest match would be evidence of very
// little.
//
// ABSENT IS NOT ZERO.  An empty table legitimately accumulates to zero, so a stored zero and a
// missing accumulator are different facts.  Callers MUST keep that distinction -- conflating them
// is exactly what the iavl storage_version marker got wrong, leaving a fast index silently empty
// while claiming to be built.  See StoreAccumulatorBytes/ParseStoreAccumulator.

// StoreAccumulator is a 256-bit sum, held big-endian.
type StoreAccumulator [32]byte

// AccumulatorRowHash is the per-row contribution: sha256 over the length-prefixed key and value.
func AccumulatorRowHash(key, value []byte) [32]byte {
	h := sha256.New()
	var lenbuf [8]byte
	binary.BigEndian.PutUint64(lenbuf[:], uint64(len(key)))
	h.Write(lenbuf[:])
	h.Write(key)
	binary.BigEndian.PutUint64(lenbuf[:], uint64(len(value)))
	h.Write(lenbuf[:])
	h.Write(value)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// twoTo256 is the modulus.  Declared once; big.Int has no fixed-width type.
var twoTo256 = new(big.Int).Lsh(big.NewInt(1), 256)

func accToBig(a StoreAccumulator) *big.Int { return new(big.Int).SetBytes(a[:]) }

func bigToAcc(n *big.Int) StoreAccumulator {
	n = new(big.Int).Mod(n, twoTo256)
	var out StoreAccumulator
	b := n.Bytes()
	copy(out[32-len(b):], b) // right-aligned, so the value is big-endian and zero-padded
	return out
}

// AccumulatorAdd folds a row IN.  Use when a row is created.
func AccumulatorAdd(acc StoreAccumulator, key, value []byte) StoreAccumulator {
	rh := AccumulatorRowHash(key, value)
	return bigToAcc(new(big.Int).Add(accToBig(acc), new(big.Int).SetBytes(rh[:])))
}

// AccumulatorSub folds a row OUT.  Use when a row is deleted, and on the OLD value when a row is
// overwritten -- which is why the setters need the previous value before writing the new one.
func AccumulatorSub(acc StoreAccumulator, key, value []byte) StoreAccumulator {
	rh := AccumulatorRowHash(key, value)
	return bigToAcc(new(big.Int).Sub(accToBig(acc), new(big.Int).SetBytes(rh[:])))
}

// AccumulatorFromPrefixStore recomputes from scratch by scanning.
//
// This is the AUTHORITATIVE value and the fallback whenever the stored accumulator is absent -- a
// fresh enclave, a restored snapshot, a just-seeded table.  It is also what the shadow comparison
// checks against, so a maintained accumulator that has drifted is caught rather than believed.
// AccumulateRowWrite folds one row change into a prefix's accumulator, given the accumulator store
// and the table's own store.
//
// CALL IT BEFORE THE STORE WRITE.  An overwrite has to subtract the row's previous value, and after
// the write that value is gone.  newValue nil means a delete.
//
// A NO-OP UNTIL THE ACCUMULATOR IS ESTABLISHED.  Genesis, a mirror seed and a state-sync restore all
// write in bulk, and a value covering only "rows seen since this process started" would be worse
// than none -- it would look authoritative while being wrong.  Establishment is by full scan, so
// bulk-loaded rows are counted correctly without every bulk path needing a hook.
//
// This lives in common, taking stores rather than a keeper, because THREE different callers need
// identical arithmetic: the qadena keeper, the dsvs keeper, and the enclave.  The entire value of
// the scheme rests on the two sides computing the same number from the same rows, so there is one
// implementation and the callers are thin wrappers over it.
func AccumulateRowWrite(accStore prefix.Store, tableStore prefix.Store, pfx string, key []byte, newValue []byte) {
	acc, ok := ParseStoreAccumulator(accStore.Get([]byte(pfx)))
	if !ok {
		return
	}

	if old := tableStore.Get(key); old != nil {
		acc = AccumulatorSub(acc, key, old)
	}
	if newValue != nil {
		acc = AccumulatorAdd(acc, key, newValue)
	}
	accStore.Set([]byte(pfx), StoreAccumulatorBytes(acc))
}

func AccumulatorFromPrefixStore(prefixStore prefix.Store) (StoreAccumulator, int) {
	itr := prefixStore.Iterator(nil, nil)
	defer itr.Close()

	var acc StoreAccumulator
	count := 0
	for ; itr.Valid(); itr.Next() {
		acc = AccumulatorAdd(acc, itr.Key(), itr.Value())
		count++
	}
	return acc, count
}

// StoreAccumulatorBytes encodes for storage WITH A PRESENCE MARKER, so that a stored zero (an
// empty table, which is a real state) is distinguishable from nothing stored at all.
func StoreAccumulatorBytes(acc StoreAccumulator) []byte {
	return append([]byte{1}, acc[:]...)
}

// ParseStoreAccumulator decodes.  ok is false when the value is missing or malformed, which the
// caller must treat as "recompute", never as zero.
func ParseStoreAccumulator(b []byte) (acc StoreAccumulator, ok bool) {
	if len(b) != 33 || b[0] != 1 {
		return acc, false
	}
	copy(acc[:], b[1:])
	return acc, true
}

// AccumulatorHex renders for logs and comparison messages.
func AccumulatorHex(acc StoreAccumulator) string { return hex.EncodeToString(acc[:]) }
