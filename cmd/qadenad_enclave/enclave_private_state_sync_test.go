package main

import (
	"context"
	"strconv"
	"testing"

	"cosmossdk.io/store/prefix"

	"github.com/stretchr/testify/require"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"
	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

// transferPrivateState drives the export/import loop directly, standing in for the gRPC hop.
// Everything on either side of the wire is exercised: page building with cursors, window pruning,
// unsealing on the source, and re-sealing through the ordinary setters on the destination.
func transferPrivateState(t *testing.T, from, to *qadenaServer, height, cutoff int64, budget int) (rows, pages int) {
	t.Helper()
	var cursor privateStateCursor
	for {
		page, err := from.buildPrivateStatePage(height, cutoff, cursor, budget)
		require.NoError(t, err)

		for _, row := range page.Rows {
			require.NoError(t, to.applyPrivateStateRow(row))
			rows++
		}
		pages++

		if page.Done {
			return rows, pages
		}
		require.NotEmpty(t, page.NextCursor, "an unfinished page must carry a cursor or the transfer cannot resume")

		next, err := decodeCursor(page.NextCursor)
		require.NoError(t, err)
		require.NotEqual(t, cursor, next, "the cursor did not advance -- the transfer would loop forever")
		cursor = next

		require.Less(t, pages, 10000, "runaway paging")
	}
}

func seedTransferSource(s *qadenaServer, wallets, transfersPerWallet int, unixTime int64) {
	for w := 0; w < wallets; w++ {
		id := "wallet-" + strconv.Itoa(w)
		history := types.EncryptableScanTransferHistory{}
		for i := 0; i < transfersPerWallet; i++ {
			history.Transfers = append(history.Transfers, &types.EncryptableScanTransfer{
				UnixTime:            unixTime + int64(i),
				DestinationWalletID: "dest-" + strconv.Itoa(i),
			})
		}
		s.setScanTransferHistory(id, history)
		s.setCredentialByHash("hash-"+id, "cred-"+id)
		s.setCredentialIdentityHistory("cred-"+id, types.EncryptableCredentialIdentityHistory{
			Hashes: []string{"old-hash-" + id, "hash-" + id},
		})
		s.setProtectSubWalletIDByOriginalWalletID("orig-"+id, "sub-"+id)
		s.setRecoverOriginalWalletIDByNewWalletID("new-"+id, "orig-"+id)
	}
}

// TestPrivateStateTransferReSealsForTheDestination is the property that makes this a transfer
// rather than a copy.
//
// Product-key sealing is bound to the CPU and stable sealing to a per-node secret, so a sealed row
// is meaningless on another machine.  If anyone ever "optimises" this into a byte copy it will pass
// on one host and fail the moment two nodes sit on different CPUs -- which is why this asserts both
// that the content matches AND that the stored bytes do not.
func TestPrivateStateTransferReSealsForTheDestination(t *testing.T) {
	src := newTestEnclaveServer(t)
	dst := newTestEnclaveServer(t)

	require.NotEqual(t,
		src.getPrivateEnclaveParamsSealedTableSharedSecret(),
		dst.getPrivateEnclaveParamsSealedTableSharedSecret(),
		"both servers share a sealing secret, so this test would prove nothing")

	seedTransferSource(src, 8, 3, 10_000)
	endBlock(t, src, 5)

	rows, _ := transferPrivateState(t, src, dst, 0, 0, privateStatePageTargetBytes)
	require.Greater(t, rows, 0)

	require.Equal(t, src.privateStateDigest(0), dst.privateStateDigest(0),
		"the destination does not hold the same private content as the source")

	require.NotEqual(t,
		rawTableBytes(src, EnclaveCredentialHashKeyPrefix),
		rawTableBytes(dst, EnclaveCredentialHashKeyPrefix),
		"the two stores hold identical bytes -- this was a byte copy, which cannot work across machines")
}

// TestPrivateStateTransferPagesFaithfully forces many small pages and asserts the result is
// identical to a single-page transfer.  A cursor that skips or repeats a row would show up here as
// a digest mismatch rather than as a silently short window on a live node.
func TestPrivateStateTransferPagesFaithfully(t *testing.T) {
	src := newTestEnclaveServer(t)
	seedTransferSource(src, 25, 4, 10_000)

	oneShot := newTestEnclaveServer(t)
	_, onePages := transferPrivateState(t, src, oneShot, 0, 0, privateStatePageTargetBytes)
	require.Equal(t, 1, onePages, "the fixture is too large to land in one page; the comparison below is not what it claims")

	paged := newTestEnclaveServer(t)
	rows, pages := transferPrivateState(t, src, paged, 0, 0, 64) // tiny budget: roughly one row per page
	require.Greater(t, pages, 10, "the budget did not actually force paging")

	require.Equal(t, src.privateStateDigest(0), paged.privateStateDigest(0),
		"a paged transfer produced different content than the source")
	require.Equal(t, oneShot.privateStateDigest(0), paged.privateStateDigest(0),
		"paged and single-page transfers disagree")
	require.Equal(t, 25*5, rows, "expected five rows per wallet across the five transferred tables")
}

// TestPrivateStateTransferPrunesTheWindow -- pruning at export is not an optimisation detail, it is
// what keeps the payload bounded by a month of activity instead of by the chain's whole lifetime.
// Row count is O(every wallet that ever sent) because pruning is lazy, so on an aged chain the dead
// tail dominates.
func TestPrivateStateTransferPrunesTheWindow(t *testing.T) {
	const cutoff = 100_000

	src := newTestEnclaveServer(t)
	// live sender
	src.setScanTransferHistory("wallet-live", types.EncryptableScanTransferHistory{
		Transfers: []*types.EncryptableScanTransfer{
			{UnixTime: cutoff + 10, DestinationWalletID: "d1"},
			{UnixTime: cutoff - 10, DestinationWalletID: "d-stale"},
		},
	})
	// wallets that have not sent since long before the window; their rows survive on the source
	// only because pruning is lazy
	for i := 0; i < 5; i++ {
		src.setScanTransferHistory("wallet-dormant-"+strconv.Itoa(i), types.EncryptableScanTransferHistory{
			Transfers: []*types.EncryptableScanTransfer{{UnixTime: 5, DestinationWalletID: "d-old"}},
		})
	}

	dst := newTestEnclaveServer(t)
	transferPrivateState(t, src, dst, 0, cutoff, privateStatePageTargetBytes)

	got := dst.getScanTransferHistory("wallet-live")
	require.Len(t, got.Transfers, 1, "the stale entry inside a live sender's row was transferred")
	require.Equal(t, int64(cutoff+10), got.Transfers[0].UnixTime)

	for i := 0; i < 5; i++ {
		require.Empty(t, dst.getScanTransferHistory("wallet-dormant-"+strconv.Itoa(i)).Transfers,
			"a wholly dormant wallet's row was transferred; the dead tail is not being dropped")
	}

	// and the two agree on what matters -- the window as the scan would read it
	require.Equal(t, src.digestScanTransferHistory(cutoff), dst.digestScanTransferHistory(cutoff))
}

// TestPrivateStateTransferOmitsKeyMaterialAndOutbox pins what must NEVER cross the wire.  A future
// change that adds a table to privateStateTables without thinking will trip this.
func TestPrivateStateTransferOmitsKeyMaterialAndOutbox(t *testing.T) {
	for _, tbl := range privateStateTables {
		switch tbl.prefix {
		case EnclaveSSIntervalSharesKeyPrefix, EnclaveSSIntervalPrivKKeyPrefix, EnclaveSSIntervalOwnersKeyPrefix:
			t.Fatalf("%s is key material and must never be transferred: shares are per-node by construction and getSSPrivK reconstructs the rest from owners at runtime", tbl.prefix)
		case EnclaveOutboxKeyPrefix:
			t.Fatalf("%s is a node-local delivery queue; importing it would re-deliver rows the snapshot already contains", tbl.prefix)
		case EnclavePreparedHeightKeyPrefix:
			t.Fatalf("%s is node-local height bookkeeping and must stay 0 so the first EndBlock adopts", tbl.prefix)
		case EnclaveCredentialPCXYKeyPrefix:
			t.Fatalf("%s is rebuilt locally by SetCredential from chain state; transferring it is waste", tbl.prefix)
		}
	}
}

// TestPrivateStateCursorSurvivesEncoding -- the cursor crosses the wire as opaque bytes and is the
// only thing standing between a resumed transfer and a silently skipped table.
func TestPrivateStateCursorSurvivesEncoding(t *testing.T) {
	for _, cur := range []privateStateCursor{
		{},
		{Table: 0, Key: "wallet-1"},
		{Table: 4, Key: ""},
		{Table: 2, Key: "key with spaces/and/slashes"},
	} {
		got, err := decodeCursor(encodeCursor(cur))
		require.NoError(t, err)
		require.Equal(t, cur, got)
	}

	_, err := decodeCursor([]byte("not json"))
	require.Error(t, err)

	_, err = decodeCursor(encodeCursor(privateStateCursor{Table: len(privateStateTables) + 1}))
	require.Error(t, err, "a cursor naming a table this build does not have must be refused, not silently clamped")
}

// TestPrivateStateRoundTripsThroughCompressionAndEncryption exercises the wire format itself:
// gzip-then-encrypt, in that order, because ciphertext does not compress.
func TestPrivateStateRoundTripsThroughCompressionAndEncryption(t *testing.T) {
	src := newTestEnclaveServer(t)
	seedTransferSource(src, 40, 5, 10_000)

	page, err := src.buildPrivateStatePage(0, 0, privateStateCursor{}, privateStatePageTargetBytes)
	require.NoError(t, err)
	require.NotEmpty(t, page.Rows)

	plain, err := page.Marshal()
	require.NoError(t, err)

	zipped, err := gzipBytes(plain)
	require.NoError(t, err)
	require.Less(t, len(zipped), len(plain), "the window did not compress; it is highly repetitive and should")

	back, err := gunzipBytes(zipped)
	require.NoError(t, err)
	require.Equal(t, plain, back)

	var decoded types.EnclavePrivateStatePage
	require.NoError(t, decoded.Unmarshal(back))
	require.Equal(t, len(page.Rows), len(decoded.Rows))
}

// TestPrivateStatePageStaysWithinTheTransportBudget guards the size reasoning: every hop runs on
// grpc-go's 4 MiB default with no overrides, so a page that outgrew the budget would fail at the
// transport with an error naming nothing useful.
func TestPrivateStatePageStaysWithinTheTransportBudget(t *testing.T) {
	src := newTestEnclaveServer(t)
	// deliberately more content than one page can hold
	seedTransferSource(src, 400, 20, 10_000)

	var cursor privateStateCursor
	for i := 0; ; i++ {
		page, err := src.buildPrivateStatePage(0, 0, cursor, privateStatePageTargetBytes)
		require.NoError(t, err)

		plain, err := page.Marshal()
		require.NoError(t, err)
		zipped, err := gzipBytes(plain)
		require.NoError(t, err)

		// compression must not be relied on for correctness -- the budget is enforced on plaintext
		require.LessOrEqual(t, len(zipped), privateStatePageHardLimitBytes,
			"a compressed page exceeded the transport limit")

		if page.Done {
			break
		}
		cursor, err = decodeCursor(page.NextCursor)
		require.NoError(t, err)
		require.Less(t, i, 10000, "runaway paging")
	}
}

// TestOversizedRowStillMakesProgress -- a single AML row is one sender's entire window, so a hot
// wallet can exceed the page budget on its own.  Stalling on it would be as bad as skipping it.
func TestOversizedRowStillMakesProgress(t *testing.T) {
	src := newTestEnclaveServer(t)

	big := types.EncryptableScanTransferHistory{}
	for i := 0; i < 500; i++ {
		big.Transfers = append(big.Transfers, &types.EncryptableScanTransfer{
			UnixTime:            10_000,
			DestinationWalletID: "destination-wallet-with-a-long-identifier-" + strconv.Itoa(i),
		})
	}
	src.setScanTransferHistory("wallet-hot", big)
	src.setCredentialByHash("h", "c")

	// a budget far below the size of that single row
	dst := newTestEnclaveServer(t)
	rows, pages := transferPrivateState(t, src, dst, 0, 0, 32)
	require.Equal(t, 2, rows)
	require.GreaterOrEqual(t, pages, 2)
	require.Equal(t, src.privateStateDigest(0), dst.privateStateDigest(0))
}

// TestApplyRefusesUnknownTable -- a peer on a newer build sending a table this one does not know
// must fail loudly.  Accepting the rest would produce a store that looks complete and is not.
func TestApplyRefusesUnknownTable(t *testing.T) {
	s := newTestEnclaveServer(t)
	err := s.applyPrivateStateRow(&types.EnclavePrivateStateRow{
		Table: "Enclave/SomethingFromTheFuture/value/", Key: "k", Value: []byte("v"),
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "does not know how to import")
}

// TestPrivateStateMarkersAreDurableAndDistinct -- the completed marker, not the presence of rows, is
// the authority on whether this enclave holds usable private state.  That is what lets pages be
// committed as they arrive (bounding enclave memory) without a crash leaving something that looks
// synced but is not.
func TestPrivateStateMarkersAreDurableAndDistinct(t *testing.T) {
	s := newTestEnclaveServer(t)

	require.Zero(t, s.privateStateSyncHeight())
	p, err := s.privateStateProgress()
	require.NoError(t, err)
	require.Nil(t, p)

	require.NoError(t, s.setPrivateStateProgress(privateStateProgress{Height: 60000, Cursor: []byte(`{"t":1,"k":"w"}`), Rows: 12, Pages: 3}))

	// a partially imported enclave: rows present, progress recorded, NOT complete
	p, err = s.privateStateProgress()
	require.NoError(t, err)
	require.NotNil(t, p)
	require.Equal(t, int64(60000), p.Height)
	require.Equal(t, 12, p.Rows)
	require.Zero(t, s.privateStateSyncHeight(), "an interrupted import must not report itself complete")

	require.NoError(t, s.finishPrivateStateImport(60000))
	require.Equal(t, int64(60000), s.privateStateSyncHeight())
	p, err = s.privateStateProgress()
	require.NoError(t, err)
	require.Nil(t, p, "the resume point must be cleared once the import completes")
}

func TestPrivateStateTablesAreEmptyDetectsEachTable(t *testing.T) {
	for _, tbl := range privateStateTables {
		s := newTestEnclaveServer(t)
		empty, _ := s.privateStateTablesAreEmpty()
		require.True(t, empty)

		switch tbl.prefix {
		case EnclaveScanTransferHistoryKeyPrefix:
			s.setScanTransferHistory("w", types.EncryptableScanTransferHistory{
				Transfers: []*types.EncryptableScanTransfer{{UnixTime: 1}},
			})
		case EnclaveCredentialHashKeyPrefix:
			s.setCredentialByHash("h", "c")
		case EnclaveCredentialHashesByCredentialIDKeyPrefix:
			s.setCredentialIdentityHistory("c", types.EncryptableCredentialIdentityHistory{Hashes: []string{"h"}})
		case EnclaveProtectSubWalletIDByOriginalWalletIDKeyPrefix:
			s.setProtectSubWalletIDByOriginalWalletID("o", "s")
		case EnclaveRecoverOriginalWalletIDByNewWalletIDKeyPrefix:
			s.setRecoverOriginalWalletIDByNewWalletID("n", "o")
		default:
			t.Fatalf("no emptiness probe for %s -- a new transferred table needs one here, or an import could silently overwrite it", tbl.prefix)
		}

		empty, name := s.privateStateTablesAreEmpty()
		require.False(t, empty, "%s holds a row but the store reported empty", tbl.prefix)
		require.Equal(t, tbl.prefix, name)
	}
}

// TestTransferredWindowProducesTheSameVerdict is the consensus-level statement, and the reason any
// of this exists: two enclaves holding the same window must reach the same conclusion about the
// same transfer.  It is the unit-scale form of "does not fork".
func TestTransferredWindowProducesTheSameVerdict(t *testing.T) {
	const cutoff = 1_000

	src := newTestEnclaveServer(t)
	// a sender several sub-threshold transfers into the window
	history := types.EncryptableScanTransferHistory{}
	for i := 0; i < 4; i++ {
		history.Transfers = append(history.Transfers, &types.EncryptableScanTransfer{
			UnixTime:            cutoff + int64(i) + 1,
			DestinationWalletID: "same-destination",
		})
	}
	src.setScanTransferHistory("structuring-wallet", history)

	dst := newTestEnclaveServer(t)
	transferPrivateState(t, src, dst, 0, cutoff, privateStatePageTargetBytes)

	// the aggregate input to the AML rule must be identical on both, entry for entry
	a := src.getScanTransferHistory("structuring-wallet")
	b := dst.getScanTransferHistory("structuring-wallet")
	require.Equal(t, len(a.Transfers), len(b.Transfers), "the two nodes would aggregate a different number of transfers")
	for i := range a.Transfers {
		require.Equal(t, a.Transfers[i].UnixTime, b.Transfers[i].UnixTime)
		require.Equal(t, a.Transfers[i].DestinationWalletID, b.Transfers[i].DestinationWalletID)
	}

	// and pruning at a shared cutoff keeps them equal, which is what a live scan does first
	require.Equal(t,
		len(c.PruneExpired(a.Transfers, cutoff)),
		len(c.PruneExpired(b.Transfers, cutoff)))
}

// TestJarRegulatorMismatchIsRefused -- the params from sync-enclave arrive from a seed this node
// cannot authenticate, so they are checked against consensus at the first opportunity instead.  The
// mirror push delivers the chain's jar->regulator binding while we still hold what the seed said.
func TestJarRegulatorMismatchIsRefused(t *testing.T) {
	s := newTestEnclaveServer(t)
	s.setSharedEnclaveParamsJarInfo("jar1", "jarPubK", "jarPrivK", "jarArmorPrivK")
	s.setSharedEnclaveParamsRegulatorInfo("regulator1", "rPubK", "rPrivK", "rArmorPrivK")

	// the chain agrees -- accepted
	_, err := s.SetJarRegulator(context.Background(), &types.JarRegulator{JarID: "jar1", RegulatorID: "regulator1"})
	require.NoError(t, err)

	// the chain says this jar answers to a different regulator -- the seed lied, or was not the
	// seed we thought
	_, err = s.SetJarRegulator(context.Background(), &types.JarRegulator{JarID: "jar1", RegulatorID: "regulator-impostor"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "disagree with chain state")

	// a DIFFERENT jar's row says nothing about ours and must pass through untouched
	_, err = s.SetJarRegulator(context.Background(), &types.JarRegulator{JarID: "jar2", RegulatorID: "regulator2"})
	require.NoError(t, err)
}

// An uninitialised enclave holds no jar, so there is nothing to contradict; the push must not be
// blocked before sync-enclave has run.
func TestJarRegulatorCheckSkippedWhenUninitialised(t *testing.T) {
	s := newTestEnclaveServer(t)
	_, err := s.SetJarRegulator(context.Background(), &types.JarRegulator{JarID: "jar1", RegulatorID: "regulator1"})
	require.NoError(t, err)
}

// TestTransferServesExactlyTheRequestedHeight is the property the whole handoff turns on.
//
// The joiner asks for the height chain state-sync stopped at, which is also the height block-sync
// is about to continue from -- so what arrives must be the state AFTER executing that block and
// before executing the next.  Off by one in either direction is a silent fork rather than an error:
// one block short leaves out whatever that block did to the AML window, one block long includes a
// block the joiner is about to execute for itself and double-counts it.
func TestTransferServesExactlyTheRequestedHeight(t *testing.T) {
	src := newTestEnclaveServer(t)

	// a distinct, identifiable window at each of three consecutive heights
	for h := int64(1); h <= 3; h++ {
		src.setScanTransferHistory("wallet-a", types.EncryptableScanTransferHistory{
			Transfers: []*types.EncryptableScanTransfer{
				{UnixTime: 1000 + h, DestinationWalletID: "dest-at-height-" + strconv.FormatInt(h, 10)},
			},
		})
		src.setCredentialByHash("hash-at-"+strconv.FormatInt(h, 10), "cred-"+strconv.FormatInt(h, 10))
		endBlock(t, src, h)
	}

	for _, target := range []int64{1, 2, 3} {
		t.Run("height-"+strconv.FormatInt(target, 10), func(t *testing.T) {
			dst := newTestEnclaveServer(t)

			// serve pinned to the target height, exactly as QueryEnclavePrivateState does
			require.NoError(t, src.withHeightPinned(target, func() error {
				var cursor privateStateCursor
				for {
					page, err := src.buildPrivateStatePage(target, 0, cursor, privateStatePageTargetBytes)
					if err != nil {
						return err
					}
					require.Equal(t, target, page.Height, "the page must carry the height it was built at")
					for _, row := range page.Rows {
						require.NoError(t, dst.applyPrivateStateRow(row))
					}
					if page.Done {
						return nil
					}
					cursor, err = decodeCursor(page.NextCursor)
					require.NoError(t, err)
				}
			}))

			// the window must be the one written AT the target height, not before or after
			got := dst.getScanTransferHistory("wallet-a")
			require.Len(t, got.Transfers, 1)
			require.Equal(t, "dest-at-height-"+strconv.FormatInt(target, 10), got.Transfers[0].DestinationWalletID,
				"served the window from the wrong height")

			// Probe the hash INDEX directly.  getCredentialByHash resolves on through to the
			// Credential row, which lives in a mirror table the transfer deliberately does not
			// carry -- it arrives from chain state via the store push -- so it would report
			// not-found here even for an index row that transferred perfectly.
			for h := target + 1; h <= 3; h++ {
				require.False(t, credentialHashIndexHas(dst, "hash-at-"+strconv.FormatInt(h, 10)),
					"a row first written at height %d leaked into a transfer pinned to height %d", h, target)
			}
			for h := int64(1); h <= target; h++ {
				require.True(t, credentialHashIndexHas(dst, "hash-at-"+strconv.FormatInt(h, 10)),
					"a row written at height %d is missing from a transfer pinned to height %d", h, target)
			}

			// and the digests agree at that height, which is the check a live node would run
			var srcDigest map[string]string
			require.NoError(t, src.withHeightPinned(target, func() error {
				srcDigest = src.privateStateDigest(0)
				return nil
			}))
			require.Equal(t, srcDigest, dst.privateStateDigest(0))
		})
	}
}

// credentialHashIndexHas reads the hash index alone, without following it to the Credential row.
func credentialHashIndexHas(s *qadenaServer, credentialHash string) bool {
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(EnclaveCredentialHashKeyPrefix))
	return store.Get(s.MustSealStable(EnclaveKeyKey(credentialHash))) != nil
}
