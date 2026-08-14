package app

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"strings"

	"cosmossdk.io/store/rootmulti"
	storetypes "cosmossdk.io/store/types"
)

// assertStoresAreReadable refuses to start on a store that the chain believes holds data but that
// yields nothing when read.
//
// WHY A HASH CANNOT CATCH THIS.  A snapshot restore imports IAVL tree nodes and nothing else.  Reads
// are not served from those nodes: when fast storage is enabled they come from the FAST INDEX, a flat
// key->value cache that is derived state, is not part of the app hash, and is not carried in the
// snapshot (SnapshotItem has no variant that could express it).  iavl rebuilds that index lazily on
// load and then stamps a completion marker.
//
// If the rebuild runs before the imported nodes are durable, it walks a tree that yields nothing,
// writes ZERO fast nodes, stamps itself complete, and the index stays empty for the life of the
// database.  Observed on this chain: a state-synced node restored a staking store of 10,011 entries
// whose root node was perfect -- correct hash, correct size, all 20,021 nodes on disk -- and whose
// every read returned nil.  The failure is invisible to every check the node makes, because they all
// stop at the root:
//
//	buildCommitInfo reads the root hash   -> commit info correct
//	Info returns it                       -> THE APP HASH IS THE ROOT HASH, so the light client verifies
//	Size() reads the root's size field    -> reports 10,011
//	a keeper reads a key                  -> nil, AND NO ERROR
//
// The first thing to notice was x/mint dereferencing an empty bond denom four frames from the cause,
// via staking's GetParams turning a missing key into zero-value params with a nil error.  That is
// luck, not detection.
//
// So this check does the one thing no hash can: it TRAVERSES.  A store whose recorded commit hash is
// not the empty-tree hash must yield at least one key.  Cost is one iterator seek per store at
// startup, and it is the only place this class of corruption can be caught before the chain builds
// on top of it.
func (app *App) assertStoresAreReadable() error {
	rms, ok := app.CommitMultiStore().(*rootmulti.Store)
	if !ok {
		// Not the multistore this check understands; nothing to assert rather than a false alarm.
		return nil
	}

	version := rms.LastCommitID().Version
	if version == 0 {
		return nil // nothing committed yet: a fresh node, not a restored one
	}

	commitInfo, err := rms.GetCommitInfo(version)
	if err != nil {
		// No commit info is normal on some paths and is not evidence of damage.
		return nil
	}

	// An IAVL store with no entries commits as the hash of nothing, which is how a legitimately
	// empty store (authz, nft, params on this chain) is told apart from one that lost its contents.
	emptyTree := sha256.Sum256(nil)

	var broken []string
	for _, si := range commitInfo.StoreInfos {
		hash := si.CommitId.Hash
		if len(hash) == 0 || bytes.Equal(hash, emptyTree[:]) {
			continue
		}

		store, ok := rms.GetStoreByName(si.Name).(storetypes.KVStore)
		if !ok {
			continue // transient or non-KV store; nothing to traverse
		}

		it := store.Iterator(nil, nil)
		hasAny := it.Valid()
		_ = it.Close()

		if !hasAny {
			broken = append(broken, si.Name)
		}
	}

	if len(broken) == 0 {
		return nil
	}

	return fmt.Errorf(`store(s) %s commit to a non-empty hash but read as empty.

This is the state a snapshot restore leaves when the fast-node index was not rebuilt: the IAVL tree
is intact and correctly hashed, so the app hash verifies and nothing else notices, but every read is
served from an empty index and returns nil. A node started in this state does not fail -- it runs
with silently missing state and forks.

Repair it in place, with the node stopped:

    qadenad repair-fast-index --home %s

That rebuilds the index from the tree already on disk; no re-sync is needed. If it reports nothing to
repair, this is a different fault and the store really is missing data -- re-join from scratch`,
		strings.Join(broken, ", "), app.BaseApp.Name())
}
