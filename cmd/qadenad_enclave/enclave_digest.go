package main

// Canonical digests of the enclave-PRIVATE tables.
//
// GetStoreHash already compares the nine chain-mirrored prefixes, and it works because those hold
// the chain's own bytes verbatim on every node.  It cannot be extended to the private tables, and
// the reason is structural rather than incidental: MustSeal is NONDETERMINISTIC (a fresh nonce per
// call) and MustSealStable derives from SealedTableSharedSecret, which is minted per node and never
// leaves it.  Two correct enclaves therefore hold completely different bytes for identical content,
// so any hash over stored bytes compares nothing.
//
// The digest here hashes the PLAINTEXT instead -- unsealed keys and values, sorted by key -- which
// is identical on two nodes that agree and different on two that do not.  That is what makes it
// possible to answer "did this import land correctly?" and "do these two nodes actually hold the
// same private state at height H?", neither of which had an answer before.
//
// The AML window is digested through the same rolling-window prune the write path applies, for a
// reason that matters: pruning is LAZY (a wallet's stale entries survive until it next sends), so
// two nodes that agree completely about consensus can still hold different dead entries -- one
// having pruned a wallet the other has not touched since.  Digesting the raw table would report
// those as divergence.  Digesting the pruned view compares exactly what the scan would read.
//
// Deliberately NOT exposed to peers over the chain.  A digest is a fingerprint of private data, and
// an attacker able to request one at arbitrary heights could confirm guesses about who transacted
// with whom.  This is a local diagnostic and a test oracle, reachable only from a node's own
// enclave socket.

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"sort"

	"cosmossdk.io/store/prefix"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"
	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

// digestEntry is one canonicalized row.
type digestEntry struct {
	key   string
	value []byte
}

// hashEntries folds sorted entries into one hash.  Both key and value are LENGTH-PREFIXED before
// being fed in, so that ("ab","c") and ("a","bc") cannot collide -- without that, a digest match
// would be evidence of very little.
func hashEntries(entries []digestEntry) string {
	sort.Slice(entries, func(i, j int) bool { return entries[i].key < entries[j].key })

	h := sha256.New()
	var lenbuf [8]byte
	for _, e := range entries {
		binary.BigEndian.PutUint64(lenbuf[:], uint64(len(e.key)))
		h.Write(lenbuf[:])
		h.Write([]byte(e.key))
		binary.BigEndian.PutUint64(lenbuf[:], uint64(len(e.value)))
		h.Write(lenbuf[:])
		h.Write(e.value)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// stripKeySeparator removes the trailing separator EnclaveKeyKey appends, so the digest is over the
// logical key rather than its storage encoding.
func stripKeySeparator(k []byte) string {
	if len(k) == 0 {
		return ""
	}
	return string(k[:len(k)-1])
}

// digestSealedStringTable covers the tables whose value is a sealed EnclaveStoreString.
func (s *qadenaServer) digestSealedStringTable(pfx string) string {
	entries := make([]digestEntry, 0)
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(pfx))
	itr := store.Iterator(nil, nil)
	defer itr.Close()
	for ; itr.Valid(); itr.Next() {
		var val types.EnclaveStoreString
		s.Cdc.MustUnmarshal(s.MustUnseal(itr.Value()), &val)
		entries = append(entries, digestEntry{
			key:   stripKeySeparator(s.MustUnsealStable(itr.Key())),
			value: []byte(val.GetS()),
		})
	}
	return hashEntries(entries)
}

// digestPlainStringTable covers the unsealed tables (CredentialPCXY), whose keys are stored as
// written and whose values are plain EnclaveStoreString.
func (s *qadenaServer) digestPlainStringTable(pfx string) string {
	entries := make([]digestEntry, 0)
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(pfx))
	itr := store.Iterator(nil, nil)
	defer itr.Close()
	for ; itr.Valid(); itr.Next() {
		var val types.EnclaveStoreString
		s.Cdc.MustUnmarshal(itr.Value(), &val)
		entries = append(entries, digestEntry{
			key:   stripKeySeparator(itr.Key()),
			value: []byte(val.GetS()),
		})
	}
	return hashEntries(entries)
}

// digestCredentialIdentityHistory covers the alias index, whose value is a repeated-field proto.
// The hash list is sorted before hashing: it is an append-ordered slice, and two nodes that learned
// the same aliases in a different order hold the same information.
func (s *qadenaServer) digestCredentialIdentityHistory() string {
	entries := make([]digestEntry, 0)
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(EnclaveCredentialHashesByCredentialIDKeyPrefix))
	itr := store.Iterator(nil, nil)
	defer itr.Close()
	for ; itr.Valid(); itr.Next() {
		var history types.EncryptableCredentialIdentityHistory
		s.Cdc.MustUnmarshal(s.MustUnseal(itr.Value()), &history)

		hashes := append([]string(nil), history.Hashes...)
		sort.Strings(hashes)

		h := sha256.New()
		var lenbuf [8]byte
		for _, hs := range hashes {
			binary.BigEndian.PutUint64(lenbuf[:], uint64(len(hs)))
			h.Write(lenbuf[:])
			h.Write([]byte(hs))
		}
		entries = append(entries, digestEntry{
			key:   stripKeySeparator(s.MustUnsealStable(itr.Key())),
			value: h.Sum(nil),
		})
	}
	return hashEntries(entries)
}

// digestScanTransferHistory covers the AML window, pruned to cutoffUnix exactly as the write path
// prunes it.  A cutoff of 0 digests the table as stored, which is what a rollback test wants; a
// real comparison between two nodes must pass the same cutoff to both.
//
// A wallet whose entries all fall outside the window contributes NOTHING, not an empty row -- so a
// node that has pruned a dormant wallet and one that has not still digest identically.
func (s *qadenaServer) digestScanTransferHistory(cutoffUnix int64) string {
	entries := make([]digestEntry, 0)
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(EnclaveScanTransferHistoryKeyPrefix))
	itr := store.Iterator(nil, nil)
	defer itr.Close()
	for ; itr.Valid(); itr.Next() {
		var history types.EncryptableScanTransferHistory
		s.Cdc.MustUnmarshal(s.MustUnseal(itr.Value()), &history)

		if cutoffUnix > 0 {
			history.Transfers = c.PruneExpired(history.Transfers, cutoffUnix)
		}
		if len(history.Transfers) == 0 {
			continue
		}

		entries = append(entries, digestEntry{
			key: stripKeySeparator(s.MustUnsealStable(itr.Key())),
			// deterministic here because both nodes run the same binary and the message has no map
			// fields, whose iteration order proto marshalling does not fix
			value: s.Cdc.MustMarshal(&history),
		})
	}
	return hashEntries(entries)
}

// privateStateDigest is the whole private surface, per prefix.
//
// Keyed by prefix rather than folded into one hash so a mismatch NAMES the table that differs.
// "the private state differs" sends an operator reading every table; "ScanTransferHistory differs,
// the rest match" is most of a diagnosis.
func (s *qadenaServer) privateStateDigest(windowCutoffUnix int64) map[string]string {
	return map[string]string{
		EnclaveScanTransferHistoryKeyPrefix:                  s.digestScanTransferHistory(windowCutoffUnix),
		EnclaveCredentialHashKeyPrefix:                       s.digestSealedStringTable(EnclaveCredentialHashKeyPrefix),
		EnclaveCredentialHashesByCredentialIDKeyPrefix:       s.digestCredentialIdentityHistory(),
		EnclaveProtectSubWalletIDByOriginalWalletIDKeyPrefix: s.digestSealedStringTable(EnclaveProtectSubWalletIDByOriginalWalletIDKeyPrefix),
		EnclaveRecoverOriginalWalletIDByNewWalletIDKeyPrefix: s.digestSealedStringTable(EnclaveRecoverOriginalWalletIDByNewWalletIDKeyPrefix),
		EnclaveCredentialPCXYKeyPrefix:                       s.digestPlainStringTable(EnclaveCredentialPCXYKeyPrefix),
	}
}
