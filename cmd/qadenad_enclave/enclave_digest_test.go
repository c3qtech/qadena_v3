package main

import (
	"context"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"cosmossdk.io/store/prefix"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"
	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

// seedPrivateTables writes one row into each private table, so a digest over them is non-trivial.
// Values are deliberately identical between callers -- the tests below turn on whether two servers
// holding the SAME content digest the same, so the content has to be genuinely the same.
func seedPrivateTables(s *qadenaServer, unixTime int64) {
	s.setScanTransferHistory("wallet-a", types.EncryptableScanTransferHistory{
		Transfers: []*types.EncryptableScanTransfer{
			{UnixTime: unixTime, DestinationWalletID: "wallet-b"},
		},
	})
	s.setCredentialByHash("hash-1", "cred-1")
	s.setCredentialIdentityHistory("cred-1", types.EncryptableCredentialIdentityHistory{
		Hashes: []string{"hash-0", "hash-1"},
	})
	s.setProtectSubWalletIDByOriginalWalletID("orig-1", "sub-1")
	s.setRecoverOriginalWalletIDByNewWalletID("new-1", "orig-1")
}

// TestPrivateStateDigestIsIdenticalAcrossSealingSecrets is the property the digest exists for, and
// the one that makes it a usable oracle at all.
//
// Two enclaves that agree about private state hold COMPLETELY DIFFERENT BYTES for it: MustSeal
// picks a fresh nonce per call, and MustSealStable derives from a per-node SealedTableSharedSecret
// that never leaves the node.  Any hash over stored bytes therefore compares nothing.  If this test
// ever fails, the digest has started depending on sealing and is worthless for comparing nodes.
func TestPrivateStateDigestIsIdenticalAcrossSealingSecrets(t *testing.T) {
	a := newTestEnclaveServer(t)
	b := newTestEnclaveServer(t)

	require.NotEqual(t,
		a.getPrivateEnclaveParamsSealedTableSharedSecret(),
		b.getPrivateEnclaveParamsSealedTableSharedSecret(),
		"the two servers must have different stable-sealing secrets or this test proves nothing")

	seedPrivateTables(a, 1000)
	seedPrivateTables(b, 1000)

	da := a.privateStateDigest(0)
	db := b.privateStateDigest(0)
	require.Equal(t, da, db, "identical private content digested differently on two nodes -- the digest is sealing-dependent")

	// and prove the raw bytes really do differ, so the equality above is a real result rather than
	// an accident of both stores being empty
	require.NotEqual(t,
		rawTableBytes(a, EnclaveCredentialHashKeyPrefix),
		rawTableBytes(b, EnclaveCredentialHashKeyPrefix),
		"the two stores hold identical bytes, so this test never exercised re-sealing")
}

// rawTableBytes concatenates the stored (still-sealed) bytes of a table, for asserting that two
// stores differ underneath a matching digest.
func rawTableBytes(s *qadenaServer, pfx string) []byte {
	out := make([]byte, 0)
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(pfx))
	itr := store.Iterator(nil, nil)
	defer itr.Close()
	for ; itr.Valid(); itr.Next() {
		out = append(out, itr.Key()...)
		out = append(out, itr.Value()...)
	}
	return out
}

func TestPrivateStateDigestChangesWithContent(t *testing.T) {
	s := newTestEnclaveServer(t)
	seedPrivateTables(s, 1000)
	before := s.privateStateDigest(0)

	s.setCredentialByHash("hash-2", "cred-2")
	after := s.privateStateDigest(0)

	require.NotEqual(t, before[EnclaveCredentialHashKeyPrefix], after[EnclaveCredentialHashKeyPrefix],
		"adding a credential hash did not change that table's digest")
	require.Equal(t, before[EnclaveScanTransferHistoryKeyPrefix], after[EnclaveScanTransferHistoryKeyPrefix],
		"changing one table changed another's digest -- the digests are not per-table")
}

// TestDigestKeyValueSplitIsUnambiguous pins the length prefixing.  Without it, key "ab" with value
// "c" and key "a" with value "bc" fold to the same bytes, and a digest match would be evidence of
// very little.
func TestDigestKeyValueSplitIsUnambiguous(t *testing.T) {
	one := hashEntries([]digestEntry{{key: "ab", value: []byte("c")}})
	two := hashEntries([]digestEntry{{key: "a", value: []byte("bc")}})
	require.NotEqual(t, one, two, "key/value boundary is not encoded; the digest is ambiguous")
}

func TestDigestIsOrderIndependent(t *testing.T) {
	forward := hashEntries([]digestEntry{{key: "a", value: []byte("1")}, {key: "b", value: []byte("2")}})
	reverse := hashEntries([]digestEntry{{key: "b", value: []byte("2")}, {key: "a", value: []byte("1")}})
	require.Equal(t, forward, reverse, "digest depends on iteration order")
}

// TestScanHistoryDigestIgnoresEntriesOutsideTheWindow is what keeps a state-synced node comparable
// to one that has been running since genesis.
//
// Window pruning is LAZY: a wallet's stale entries survive until it next sends.  So two nodes that
// agree perfectly about consensus can still hold different dead rows -- one having pruned a wallet
// the other has not touched in months.  Digesting the raw table would report that as divergence and
// send someone chasing a fork that does not exist.
func TestScanHistoryDigestIgnoresEntriesOutsideTheWindow(t *testing.T) {
	const cutoff = 5000

	// pruned: only a live entry.  unpruned: the same live entry plus stale ones it never cleaned up.
	pruned := newTestEnclaveServer(t)
	pruned.setScanTransferHistory("wallet-a", types.EncryptableScanTransferHistory{
		Transfers: []*types.EncryptableScanTransfer{
			{UnixTime: 6000, DestinationWalletID: "wallet-b"},
		},
	})

	unpruned := newTestEnclaveServer(t)
	unpruned.setScanTransferHistory("wallet-a", types.EncryptableScanTransferHistory{
		Transfers: []*types.EncryptableScanTransfer{
			{UnixTime: 100, DestinationWalletID: "wallet-x"},
			{UnixTime: 4999, DestinationWalletID: "wallet-y"},
			{UnixTime: 6000, DestinationWalletID: "wallet-b"},
		},
	})
	// a wholly dormant wallet, present on one node only
	unpruned.setScanTransferHistory("wallet-dormant", types.EncryptableScanTransferHistory{
		Transfers: []*types.EncryptableScanTransfer{
			{UnixTime: 12, DestinationWalletID: "wallet-z"},
		},
	})

	require.Equal(t,
		pruned.digestScanTransferHistory(cutoff),
		unpruned.digestScanTransferHistory(cutoff),
		"stale entries outside the window changed the digest -- lazy pruning would read as divergence")

	// without the cutoff they must differ, or the assertion above proves nothing
	require.NotEqual(t,
		pruned.digestScanTransferHistory(0),
		unpruned.digestScanTransferHistory(0),
		"the two stores are identical, so the window test never exercised pruning")

	// and an entry exactly ON the boundary is inside the window, matching PruneExpired
	boundary := newTestEnclaveServer(t)
	boundary.setScanTransferHistory("wallet-a", types.EncryptableScanTransferHistory{
		Transfers: []*types.EncryptableScanTransfer{
			{UnixTime: cutoff, DestinationWalletID: "wallet-b"},
			{UnixTime: 6000, DestinationWalletID: "wallet-b"},
		},
	})
	require.NotEqual(t, pruned.digestScanTransferHistory(cutoff), boundary.digestScanTransferHistory(cutoff),
		"an entry recorded exactly at the cutoff must be kept, as PruneExpired keeps it")
}

// TestDigestIsHeightPinned ties the digest to withHeightPinned, which is how a peer will be asked
// "what did you hold at H?" during a private-state transfer.
func TestDigestIsHeightPinned(t *testing.T) {
	s := newTestEnclaveServer(t)

	seedPrivateTables(s, 1000)
	endBlock(t, s, 10)
	atTen := s.privateStateDigest(0)

	s.setCredentialByHash("hash-later", "cred-later")
	endBlock(t, s, 11)
	atEleven := s.privateStateDigest(0)

	require.NotEqual(t, atTen[EnclaveCredentialHashKeyPrefix], atEleven[EnclaveCredentialHashKeyPrefix],
		"height 11 added a row but the current digest did not change")

	var pinned map[string]string
	require.NoError(t, s.withHeightPinned(10, func() error {
		pinned = s.privateStateDigest(0)
		return nil
	}))
	require.Equal(t, atTen, pinned, "a digest pinned to height 10 did not match what height 10 actually held")

	// the pin must be released -- a server left pointing at the past would answer every subsequent
	// read from a stale version while writing to the present
	require.Equal(t, atEleven, s.privateStateDigest(0), "the height pin was not restored")
}

func TestDigestAtPrunedHeightIsRefusedByName(t *testing.T) {
	s := newPrunedTestEnclaveServer(t, 10, 5)
	for h := int64(1); h <= 40; h++ {
		setMirrorRow(s, "row", "h"+strconv.FormatInt(h, 10))
		endBlock(t, s, h)
	}

	err := s.withHeightPinned(1, func() error { return nil })
	require.Error(t, err)
	require.Contains(t, err.Error(), "pruned", "a below-horizon pin must say why, not fail obscurely")
}

// TestExportPrivateStateCarriesTheAMLWindow -- the window's absence from the export is what made
// the 2026-08-09 fork undiagnosable: two nodes disagreed about executing a block, and the one input
// that decides that disagreement could not be dumped from either of them.
func TestExportPrivateStateCarriesTheAMLWindow(t *testing.T) {
	s := newTestEnclaveServer(t)
	seedPrivateTables(s, 1000)
	outboxAppend(s, outboxWalletsKey, "wallet-pending")
	endBlock(t, s, 7)

	reply, err := s.ExportPrivateState(context.Background(), &types.MsgExportPrivateState{})
	require.NoError(t, err)

	require.Contains(t, reply.State, "ScanTransferHistoryMap")
	require.Contains(t, reply.State, "wallet-a", "the AML window's sender is missing from the dump")
	require.Contains(t, reply.State, "wallet-b", "the AML window's destination is missing from the dump")
	require.Contains(t, reply.State, "wallet-pending", "the outbox is missing from the dump")
	require.Contains(t, reply.State, "PreparedHeight")
}

// PruneExpired is the shared boundary rule; pin it here too so the digest and the write path cannot
// drift apart silently.
func TestPruneExpiredKeepsTheBoundaryEntry(t *testing.T) {
	transfers := []*types.EncryptableScanTransfer{
		{UnixTime: 99}, {UnixTime: 100}, {UnixTime: 101},
	}
	kept := c.PruneExpired(transfers, 100)
	require.Len(t, kept, 2)
	require.Equal(t, int64(100), kept[0].UnixTime, "the entry exactly at the cutoff must survive")
}
