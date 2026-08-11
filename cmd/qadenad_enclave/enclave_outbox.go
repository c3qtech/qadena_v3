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
