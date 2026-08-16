package main

// The outbox: the enclave->chain delivery queues, in VERSIONED state.
//
// Every block, EnclaveEndBlock on the chain drains four queues out of the enclave -- changed
// wallets, changed/removed credentials, changed recover keys, new suspicious transactions -- and
// writes them into block state.  Those queues used to be plain slices on qadenaServer, which had
// two failure modes:
//
//   crash-loss     an enclave restart between a write and the next EndBlock lost the queue
//                  entries permanently; enclaveSynchronizeStores then OVERWROTE the enclave's
//                  newer row from the chain's stale copy.
//
//   drain-loss     the drain RPCs cleared the slices inside the same call that returned the
//                  data.  If the chain then failed before committing the block (a later sync
//                  step halting the node, a crash before Commit), the rows were gone from the
//                  enclave while the block that would have carried them never existed.
//
// Moving the queues into the versioned store closes both, and makes ROLLBACK the abort path of a
// two-phase commit: appends go through the transaction cache (so a failed transaction's queue
// entries vanish with its writes -- previously they lingered and re-emitted whatever the store
// held), drains delete the rows through the same cache (so "cleared" becomes durable exactly
// when the block that consumed the rows commits), and a rollback of the tree resurrects
// precisely the rows the unwound blocks must re-deliver when they re-execute.
//
// The delivery-order invariant (see EnclaveEndBlock in x/qadena/keeper/enclave_grpc_client.go)
// is why this matters: rows must land at the height that produced them, so the only sound
// recovery from a missed delivery is re-executing that height -- which is exactly what a
// rollback plus replay now does, with the outbox rows travelling along.
//
// Each queue is ONE row holding a JSON-encoded list: order-preserving (suspicious-transaction
// IDs are assigned in delivery order on the chain side), read-modify-write per append (fine --
// the queues are drained every block, so they stay small), and enclave-local (the prefix is
// deliberately NOT in GetStoreHash's key list; the QUEUES differ between nodes mid-recovery
// even when the state agrees).

import (
	"encoding/json"

	"strconv"

	"cosmossdk.io/store/prefix"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"
	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

const (
	EnclaveOutboxKeyPrefix = "Enclave/Outbox/value/"

	outboxWalletsKey            = "wallets/"
	outboxChangedCredentialsKey = "changedCredentials/"
	outboxRemovedCredentialsKey = "removedCredentials/"
	outboxRecoverKeysKey        = "recoverKeys/"
	outboxSuspiciousKey         = "suspicious/"
)

// outboxCredentialKey mirrors the unexported CredentialKey with exported fields so it survives
// JSON round-tripping.
type outboxCredentialKey struct {
	CredentialID   string `json:"id"`
	CredentialType string `json:"type"`
}

// outboxDump is every queue at once, for the debug export.  A fork diagnosis needs to know what
// the enclave was holding to hand the chain but had not yet delivered -- an outbox that is
// non-empty at a height where the peer's is empty is a divergence in itself.
type outboxDump struct {
	Wallets            []string
	ChangedCredentials []outboxCredentialKey
	RemovedCredentials []outboxCredentialKey
	RecoverKeys        []string
	Suspicious         []types.SuspiciousTransaction
}

func exportOutbox(s *qadenaServer) outboxDump {
	return outboxDump{
		Wallets:            outboxGet[string](s, outboxWalletsKey),
		ChangedCredentials: outboxGet[outboxCredentialKey](s, outboxChangedCredentialsKey),
		RemovedCredentials: outboxGet[outboxCredentialKey](s, outboxRemovedCredentialsKey),
		RecoverKeys:        outboxGet[string](s, outboxRecoverKeysKey),
		Suspicious:         outboxGet[types.SuspiciousTransaction](s, outboxSuspiciousKey),
	}
}

// outboxGet reads a queue.  Reads go through the transaction cache like every other versioned
// read, so a queue entry appended earlier in the same transaction is visible.
func outboxGet[T any](s *qadenaServer, key string) []T {
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(EnclaveOutboxKeyPrefix))
	b := store.Get([]byte(key))
	if b == nil {
		return nil
	}
	var list []T
	if err := json.Unmarshal(b, &list); err != nil {
		// only ever written by outboxSet below; a decode failure is corruption no fallback fixes
		panic("qadena enclave: corrupt outbox row " + key + ": " + err.Error())
	}
	return list
}

// outboxSet replaces a queue; an empty list deletes the row so an idle enclave's store carries
// no outbox residue.  Writes go through the transaction cache: an append from a failed
// transaction is discarded with the cache, and a drain's clear becomes durable exactly when the
// block that consumed the rows commits.
func outboxSet[T any](s *qadenaServer, key string, list []T) {
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(EnclaveOutboxKeyPrefix))
	if len(list) == 0 {
		store.Delete([]byte(key))
		return
	}
	b, err := json.Marshal(list)
	if err != nil {
		panic("qadena enclave: cannot encode outbox row " + key + ": " + err.Error())
	}
	store.Set([]byte(key), b)
}

func outboxAppend[T any](s *qadenaServer, key string, items ...T) {
	if len(items) == 0 {
		return
	}
	list := outboxGet[T](s, key)
	list = append(list, items...)
	outboxSet(s, key, list)
	c.LoggerDebug(logger, "outbox append "+key)
}

// outboxPageTargetBytes bounds one drain's worth of resolved rows.
//
// The binding constraint is the EPC, not the wire.  Draining turns each queued ID into a full row
// and holds every one of them at once, so an unbounded drain makes the enclave's peak memory a
// function of how busy the block was -- inside an enclave page cache measured in tens of megabytes
// and shared with everything else running.  The 4 MiB grpc-go default, which neither end overrides,
// is the second reason and the less pressing one.
//
// Matched to privateStatePageTargetBytes, which is the size the private-state sync already pages at
// inside the same EPC.
const outboxPageTargetBytes = 1 << 20

func outboxPageBudget(maxBytes uint32) int {
	b := int(maxBytes)
	if b <= 0 || b > outboxPageTargetBytes {
		return outboxPageTargetBytes
	}
	return b
}

// outboxDrainPage walks a queue from the front, resolving entries into rows until the budget is
// reached, and reports how far it got.
//
// resolve returns the row, its size, and whether it resolved at all.  An entry that does not
// resolve is still WALKED PAST rather than held back: the queue holds IDs, and an ID whose row has
// since gone is one that will never resolve, so retaining it would grow the queue without bound and
// make every later drain re-walk it.  This matches what the unpaged drain did by clearing the whole
// queue at once.
//
// `more` means "the walk stopped early", NOT "the queue is non-empty".  That distinction is what
// makes the caller's loop terminate: it is only ever true when this call consumed entries, so a
// caller that keeps calling keeps making progress.
func outboxDrainPage[T any, R any](list []T, budget int, resolve func(T) (R, int, bool)) (rows []R, consumed int, more bool) {
	used := 0
	for i, entry := range list {
		row, size, ok := resolve(entry)

		// Checked BEFORE consuming, so the entry survives for the next page.  `len(rows) > 0`
		// guarantees forward progress: a single row larger than the whole budget goes on its own
		// rather than wedging the queue forever.
		if ok && len(rows) > 0 && used+size > budget {
			return rows, i, true
		}

		if ok {
			rows = append(rows, row)
			used += size
		}
		consumed = i + 1
	}
	return rows, consumed, false
}

// outboxCommitPage writes back what a drain left behind and decides whether the caller should ask
// again.
//
// NOTHING CLEARED MEANS NOTHING MORE, whatever the walk found.  A caller that loops on `more`
// without the queue having shrunk would loop forever, and there are two ways to reach that: a
// diagnostic read with Clear unset, and a page in which no entry resolved.  Both are answered the
// same way -- report the rows, keep the queue, let the next block retry.
//
// shouldClear is the CALLER'S, deliberately, because the queues do not agree on it.  The three that
// carry IDs only clear when something resolved, so an unresolved entry survives to be retried.  The
// removed-credentials queue clears on having walked entries at all, because there "did not resolve"
// means the removal was rolled back and there is nothing left to retry -- holding those back would
// re-check them on every block forever.
func outboxCommitPage[T any](s *qadenaServer, key string, list []T, consumed int, shouldClear bool, more bool) bool {
	if !shouldClear {
		return false
	}
	c.LoggerDebug(logger, "outbox drain "+key+" consumed "+strconv.Itoa(consumed)+" of "+strconv.Itoa(len(list)))
	outboxSet(s, key, list[consumed:])
	return more
}
