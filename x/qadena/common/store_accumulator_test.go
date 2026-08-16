package common

import (
	"fmt"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

// The accumulator is a MAINTAINED INVARIANT, and this repository has been bitten twice by those --
// the iavl fast index and the CredentialPCXY index both drifted from the data they described and
// said nothing.  These tests pin the properties the maintenance depends on.

func TestAccumulatorIsOrderIndependent(t *testing.T) {
	var forward, reverse StoreAccumulator
	forward = AccumulatorAdd(forward, []byte("a"), []byte("1"))
	forward = AccumulatorAdd(forward, []byte("b"), []byte("2"))
	forward = AccumulatorAdd(forward, []byte("c"), []byte("3"))

	reverse = AccumulatorAdd(reverse, []byte("c"), []byte("3"))
	reverse = AccumulatorAdd(reverse, []byte("b"), []byte("2"))
	reverse = AccumulatorAdd(reverse, []byte("a"), []byte("1"))

	require.Equal(t, forward, reverse,
		"order matters, so a seeded enclave (key order) would never match the chain (time order)")
}

func TestAccumulatorKeyValueSplitIsUnambiguous(t *testing.T) {
	var one, two StoreAccumulator
	one = AccumulatorAdd(one, []byte("ab"), []byte("c"))
	two = AccumulatorAdd(two, []byte("a"), []byte("bc"))
	require.NotEqual(t, one, two, "key/value boundary is not encoded; a match would prove little")
}

func TestAccumulatorAddAndSubAreInverses(t *testing.T) {
	var acc StoreAccumulator
	start := acc
	acc = AccumulatorAdd(acc, []byte("k"), []byte("v"))
	require.NotEqual(t, start, acc)
	acc = AccumulatorSub(acc, []byte("k"), []byte("v"))
	require.Equal(t, start, acc, "removing a row does not undo adding it")
}

// Subtracting below zero must wrap rather than clamp, or a delete-before-add ordering (which a
// rollback can produce) would corrupt the running value permanently.
func TestAccumulatorWrapsRatherThanClamps(t *testing.T) {
	var acc StoreAccumulator
	acc = AccumulatorSub(acc, []byte("k"), []byte("v"))
	require.NotEqual(t, StoreAccumulator{}, acc, "subtracting from zero produced zero")
	acc = AccumulatorAdd(acc, []byte("k"), []byte("v"))
	require.Equal(t, StoreAccumulator{}, acc, "add did not undo a wrapped subtract")
}

// THE PROPERTY THE WHOLE DESIGN RESTS ON: maintaining incrementally must land on exactly what a
// full scan would produce, through any sequence of inserts, overwrites and deletes.
func TestIncrementalMaintenanceMatchesAFullRecompute(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	model := map[string][]byte{}
	var acc StoreAccumulator

	for i := 0; i < 2000; i++ {
		key := fmt.Sprintf("key%d", rng.Intn(50))
		switch rng.Intn(3) {
		case 0, 1: // insert or overwrite
			val := []byte(fmt.Sprintf("value%d", rng.Intn(1000)))
			if old, exists := model[key]; exists {
				acc = AccumulatorSub(acc, []byte(key), old) // the overwrite case: OLD value out first
			}
			acc = AccumulatorAdd(acc, []byte(key), val)
			model[key] = val
		case 2: // delete
			if old, exists := model[key]; exists {
				acc = AccumulatorSub(acc, []byte(key), old)
				delete(model, key)
			}
		}
	}

	var scanned StoreAccumulator
	for k, v := range model {
		scanned = AccumulatorAdd(scanned, []byte(k), v)
	}
	require.Equal(t, scanned, acc,
		"incremental value diverged from a recompute; every write path must subtract the old value")
}

// An overwrite that forgets to subtract the old value is the most likely mistake when wiring the
// setters, so make its signature explicit rather than leaving it to be discovered in production.
func TestOverwriteWithoutSubtractingOldValueDiverges(t *testing.T) {
	var correct, buggy StoreAccumulator

	correct = AccumulatorAdd(correct, []byte("k"), []byte("v1"))
	correct = AccumulatorSub(correct, []byte("k"), []byte("v1"))
	correct = AccumulatorAdd(correct, []byte("k"), []byte("v2"))

	buggy = AccumulatorAdd(buggy, []byte("k"), []byte("v1"))
	buggy = AccumulatorAdd(buggy, []byte("k"), []byte("v2")) // forgot the subtract

	require.NotEqual(t, correct, buggy)

	var scanned StoreAccumulator
	scanned = AccumulatorAdd(scanned, []byte("k"), []byte("v2"))
	require.Equal(t, scanned, correct, "the correct sequence should match a scan of the final state")
}

// Absent and zero are different facts.  An empty table accumulates to zero legitimately; a missing
// accumulator means "unknown, recompute".  Conflating them is what left an iavl fast index empty
// while its completion marker claimed otherwise.
func TestAbsentIsDistinguishableFromZero(t *testing.T) {
	zero := StoreAccumulator{}
	encoded := StoreAccumulatorBytes(zero)

	got, ok := ParseStoreAccumulator(encoded)
	require.True(t, ok, "a stored zero must decode as PRESENT")
	require.Equal(t, zero, got)

	_, ok = ParseStoreAccumulator(nil)
	require.False(t, ok, "missing must not decode as a valid zero")

	_, ok = ParseStoreAccumulator([]byte{0})
	require.False(t, ok, "malformed must not decode as a valid zero")

	_, ok = ParseStoreAccumulator(make([]byte, 33))
	require.False(t, ok, "a 33-byte blob without the presence marker must not decode")
}

func TestAccumulatorRoundTripsThroughStorage(t *testing.T) {
	var acc StoreAccumulator
	acc = AccumulatorAdd(acc, []byte("wallet1"), []byte("balance"))

	got, ok := ParseStoreAccumulator(StoreAccumulatorBytes(acc))
	require.True(t, ok)
	require.Equal(t, acc, got)
	require.Len(t, AccumulatorHex(acc), 64)
}
