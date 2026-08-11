package main

// The first Go tests in this package.  They exercise the prepare/confirm/rollback state machine
// against in-memory DBs -- nothing SGX-specific is needed: RealEnclave=false degrades sealing to
// prefix concatenation, and MustSealStable only needs a SealedTableSharedSecret to be set.

import (
	"context"
	"testing"
	"time"

	cosmossdkiolog "cosmossdk.io/log"
	"cosmossdk.io/store"
	storemetrics "cosmossdk.io/store/metrics"
	"cosmossdk.io/store/prefix"
	storetypes "cosmossdk.io/store/types"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	tmdb "github.com/cosmos/cosmos-db"
	amino "github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdktypes "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"
	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

func newTestEnclaveServer(t *testing.T) *qadenaServer {
	t.Helper()
	if logger == nil {
		logger = c.NewTMLogger("enclave-test")
	}

	storeKey := storetypes.NewKVStoreKey(types.StoreKey)
	db := tmdb.NewMemDB()
	stateStore := store.NewCommitMultiStore(db, cosmossdkiolog.NewNopLogger(), storemetrics.NewNoOpMetrics())
	stateStore.SetIAVLCacheSize(iavlCacheNodes)
	stateStore.MountStoreWithDB(storeKey, storetypes.StoreTypeIAVL, db)
	require.NoError(t, stateStore.LoadLatestVersion())

	serverCtx := sdk.NewContext(stateStore, tmproto.Header{}, false, logger)
	cacheCtx, cacheCtxWrite := serverCtx.CacheContext()

	registry := codectypes.NewInterfaceRegistry()
	cdc := amino.NewProtoCodec(registry)

	s := &qadenaServer{
		StoreKey:      storeKey,
		ServerCtx:     serverCtx,
		CacheCtx:      cacheCtx,
		CacheCtxWrite: cacheCtxWrite,
		Cdc:           cdc,
		MetaDB:        db,
		SecretsDB:     tmdb.NewMemDB(),
		RealEnclave:   false,
	}
	s.setPrivateEnclaveParamsSealedTableSharedSecret(c.GenerateSharedSecret())
	require.NoError(t, s.initSchema())
	return s
}

// setMirrorRow / getMirrorRow write and read a row under a mirror prefix through the transaction
// cache, standing in for real block execution.
func setMirrorRow(s *qadenaServer, key, val string) {
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(types.WalletKeyPrefix))
	store.Set([]byte(key), []byte(val))
}

func getMirrorRow(s *qadenaServer, key string) string {
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(types.WalletKeyPrefix))
	return string(store.Get([]byte(key)))
}

func endBlock(t *testing.T, s *qadenaServer, h int64) *types.EndBlockReply {
	t.Helper()
	r, err := s.EndBlock(context.Background(), &types.MsgEndBlock{Height: h})
	require.NoError(t, err, "EndBlock(%d)", h)
	return r
}

func TestPrepareConfirmRollbackStateMachine(t *testing.T) {
	s := newTestEnclaveServer(t)

	// a fresh enclave adopts its first height, wherever it lands (a node seeded mid-chain)
	r := endBlock(t, s, 100)
	require.Equal(t, int64(100), r.PreparedHeight)
	require.Equal(t, int64(100), s.getPreparedHeight())

	// block 101 writes a row
	setMirrorRow(s, "wallet-1", "v1")
	endBlock(t, s, 101)
	_, err := s.ConfirmHeight(context.Background(), &types.MsgConfirmHeight{Height: 101})
	require.NoError(t, err)
	require.Equal(t, int64(101), s.getConfirmedHeight())

	// block 102 changes it
	setMirrorRow(s, "wallet-1", "v2")
	endBlock(t, s, 102)
	require.Equal(t, "v2", getMirrorRow(s, "wallet-1"))

	// roll back to 101: the row reverts, the stamp reverts with the tree, the index is pruned
	rb, err := s.RollbackToHeight(context.Background(), &types.MsgRollbackToHeight{Height: 101})
	require.NoError(t, err)
	require.True(t, rb.RolledBack)
	require.Equal(t, "v1", getMirrorRow(s, "wallet-1"))
	require.Equal(t, int64(101), s.getPreparedHeight())
	require.Equal(t, int64(101), s.getConfirmedHeight())
	_, found := s.getHeightVersion(102)
	require.False(t, found, "index entry for the unwound height must be pruned")

	// the height can be re-executed with different content
	setMirrorRow(s, "wallet-1", "v2-reexecuted")
	endBlock(t, s, 102)
	require.Equal(t, "v2-reexecuted", getMirrorRow(s, "wallet-1"))
}

func TestEndBlockRefusals(t *testing.T) {
	s := newTestEnclaveServer(t)

	// height 0 is a chain binary that predates height bookkeeping
	_, err := s.EndBlock(context.Background(), &types.MsgEndBlock{Height: 0})
	require.Error(t, err)

	endBlock(t, s, 50)

	// replayed and out-of-order heights are refused, not silently committed
	_, err = s.EndBlock(context.Background(), &types.MsgEndBlock{Height: 50})
	require.Error(t, err)
	_, err = s.EndBlock(context.Background(), &types.MsgEndBlock{Height: 49})
	require.Error(t, err)

	// gaps are allowed only upward
	endBlock(t, s, 51)
}

func TestRollbackRefusalsAndDryRun(t *testing.T) {
	s := newTestEnclaveServer(t)
	endBlock(t, s, 10)
	endBlock(t, s, 11)

	// above prepared: the enclave is BEHIND that target; error, never a silent no-op
	_, err := s.RollbackToHeight(context.Background(), &types.MsgRollbackToHeight{Height: 12})
	require.Error(t, err)

	// at prepared: idempotent success without rolling anything
	r, err := s.RollbackToHeight(context.Background(), &types.MsgRollbackToHeight{Height: 11})
	require.NoError(t, err)
	require.False(t, r.RolledBack)

	// below the horizon (9 was never committed by this store): refusal by name
	_, err = s.RollbackToHeight(context.Background(), &types.MsgRollbackToHeight{Height: 9})
	require.Error(t, err)

	// dry run reports the versions without touching anything
	r, err = s.RollbackToHeight(context.Background(), &types.MsgRollbackToHeight{Height: 10, DryRun: true})
	require.NoError(t, err)
	require.False(t, r.RolledBack)
	require.Equal(t, int64(11), s.getPreparedHeight(), "dry run must not roll back")

	// and the real thing works afterwards
	r, err = s.RollbackToHeight(context.Background(), &types.MsgRollbackToHeight{Height: 10})
	require.NoError(t, err)
	require.True(t, r.RolledBack)
	require.Equal(t, int64(10), s.getPreparedHeight())
}

func TestOutOfBandCommitIsNotIndexed(t *testing.T) {
	s := newTestEnclaveServer(t)
	setMirrorRow(s, "row", "h5")
	endBlock(t, s, 5)

	// simulate SyncEnclave's out-of-band commit: cache write + direct Commit, no height stamp
	setMirrorRow(s, "row", "out-of-band")
	s.commitCache()
	cms := s.ServerCtx.MultiStore().(storetypes.CommitMultiStore)
	oob := cms.Commit()

	// the out-of-band version exists in the tree but is invisible to the height index
	_, found := s.getHeightVersion(6)
	require.False(t, found)
	require.Greater(t, oob.Version, int64(0))

	// the next real block indexes its own, later version
	endBlock(t, s, 6)
	v6, found := s.getHeightVersion(6)
	require.True(t, found)
	require.Greater(t, v6, oob.Version)

	// rolling back to 5 unwinds through the out-of-band version too
	r, err := s.RollbackToHeight(context.Background(), &types.MsgRollbackToHeight{Height: 5})
	require.NoError(t, err)
	require.True(t, r.RolledBack)
	require.Equal(t, "h5", getMirrorRow(s, "row"))
}

func TestOutboxRollsBackWithState(t *testing.T) {
	s := newTestEnclaveServer(t)
	endBlock(t, s, 5)

	// block 6: a wallet changes; the outbox entry rides the same version
	s.setWallet(types.Wallet{WalletID: "w1"})
	endBlock(t, s, 6)
	require.Equal(t, []string{"w1"}, outboxGet[string](s, outboxWalletsKey))

	// block 7: the chain drains with Clear; the clear becomes durable with block 7's commit
	reply, err := s.SyncWallets(context.Background(), &types.MsgSyncWallets{Clear: true})
	require.NoError(t, err)
	require.Len(t, reply.Wallets, 1)
	endBlock(t, s, 7)
	require.Empty(t, outboxGet[string](s, outboxWalletsKey))

	// rolling back to 6 resurrects exactly the rows block 7's re-execution must re-deliver
	r, err := s.RollbackToHeight(context.Background(), &types.MsgRollbackToHeight{Height: 6})
	require.NoError(t, err)
	require.True(t, r.RolledBack)
	require.Equal(t, []string{"w1"}, outboxGet[string](s, outboxWalletsKey))
}

func TestFailedTransactionDiscardsItsOutboxEntries(t *testing.T) {
	s := newTestEnclaveServer(t)
	endBlock(t, s, 5)

	// a transaction writes a wallet, then fails
	s.setWallet(types.Wallet{WalletID: "doomed"})
	_, err := s.TransactionComplete(context.Background(), &types.MsgTransactionComplete{Success: false})
	require.NoError(t, err)

	// its outbox entry vanished with its state -- previously the RAM queue kept it and re-emitted
	// whatever the store held
	require.Empty(t, outboxGet[string](s, outboxWalletsKey))
	endBlock(t, s, 6)
	reply, err := s.SyncWallets(context.Background(), &types.MsgSyncWallets{Clear: true})
	require.NoError(t, err)
	require.Empty(t, reply.Wallets)
}

func TestSecretsSurviveRollback(t *testing.T) {
	s := newTestEnclaveServer(t)
	endBlock(t, s, 5)

	// a key generated "at height 6" -- writes go straight to the secrets DB, not the tree
	s.setOwnersAndShare("pubkid-1", []string{"pioneer1"}, "share-1")
	s.setPrivKCache("pubkid-1", "privk-1")
	endBlock(t, s, 6)
	endBlock(t, s, 7)

	r, err := s.RollbackToHeight(context.Background(), &types.MsgRollbackToHeight{Height: 5})
	require.NoError(t, err)
	require.True(t, r.RolledBack)

	// the tree is back at height 5; the key material is intact -- THE property the secrets DB
	// exists for: its public half may already be broadcast on chain, and re-execution cannot
	// regenerate it
	share, found := s.getShare("pubkid-1")
	require.True(t, found)
	require.Equal(t, "share-1", share)
	privk, found := s.getPrivKCache("pubkid-1")
	require.True(t, found)
	require.Equal(t, "privk-1", privk)
}

func TestConfirmHeightRefusals(t *testing.T) {
	s := newTestEnclaveServer(t)
	endBlock(t, s, 5)

	// confirming a height the enclave did not prepare asserts durability of state it does not hold
	_, err := s.ConfirmHeight(context.Background(), &types.MsgConfirmHeight{Height: 4})
	require.Error(t, err)
	_, err = s.ConfirmHeight(context.Background(), &types.MsgConfirmHeight{Height: 6})
	require.Error(t, err)

	_, err = s.ConfirmHeight(context.Background(), &types.MsgConfirmHeight{Height: 5})
	require.NoError(t, err)
	require.Equal(t, int64(5), s.getConfirmedHeight())
}

func TestGetEnclaveHeightReportsWatermarks(t *testing.T) {
	s := newTestEnclaveServer(t)
	endBlock(t, s, 20)
	endBlock(t, s, 21)
	_, err := s.ConfirmHeight(context.Background(), &types.MsgConfirmHeight{Height: 21})
	require.NoError(t, err)

	h, err := s.GetEnclaveHeight(context.Background(), &types.MsgGetEnclaveHeight{})
	require.NoError(t, err)
	require.Equal(t, int64(21), h.PreparedHeight)
	require.Equal(t, int64(21), h.ConfirmedHeight)
	require.Equal(t, int64(20), h.EarliestHeight)
	require.Equal(t, enclaveSchemaVersion, h.SchemaVersion)
}

func TestGetStoreHashDoesNotMutate(t *testing.T) {
	s := newTestEnclaveServer(t)
	endBlock(t, s, 5)

	// a partially executed transaction has written into the cache
	setMirrorRow(s, "partial", "uncommitted")

	_, err := s.GetStoreHash(context.Background(), &types.MsgGetStoreHash{})
	require.NoError(t, err)

	// the read must not have promoted the cache: discarding the transaction must still discard
	// its write (this was the write-on-read bug -- GetStoreHash called commitCache)
	_, err = s.TransactionComplete(context.Background(), &types.MsgTransactionComplete{Success: false})
	require.NoError(t, err)
	require.Empty(t, getMirrorRow(s, "partial"))
}

// ---- boundary tests: the specific state classes a rollback must handle differently ----

// TestRollbackAcrossSSKeyRotation is the 2026-08-09 incident shape.  The enclave died inside
// GenerateSecretShare at block 61,050 (a 555-block rotation boundary), and the recovery question
// was whether rolling the chain back would destroy key material whose public half was already on
// chain.  It must not: the interval key ROW is a chain mirror and rolls back, while the SHARE and
// PRIVATE KEY live in the secrets DB and survive -- because a re-executed block cannot regenerate
// them (GenerateSecretShare is nondeterministic and runs outside block execution).
func TestRollbackAcrossSSKeyRotation(t *testing.T) {
	s := newTestEnclaveServer(t)

	// pre-rotation state at height 554
	s.setIntervalPublicKeyIdNoNotify(types.IntervalPublicKeyID{
		NodeID: types.SSNodeID, NodeType: types.SSNodeType, PubKID: "ss-key-old",
	})
	s.setOwnersAndShare("ss-key-old", []string{"pioneer1"}, "share-old")
	s.setPrivKCache("ss-key-old", "privk-old")
	endBlock(t, s, 554)

	// the rotation lands at 555: a new interval key on the mirror, new material in the secrets DB
	s.setIntervalPublicKeyIdNoNotify(types.IntervalPublicKeyID{
		NodeID: types.SSNodeID, NodeType: types.SSNodeType, PubKID: "ss-key-new",
	})
	s.setOwnersAndShare("ss-key-new", []string{"pioneer1"}, "share-new")
	s.setPrivKCache("ss-key-new", "privk-new")
	endBlock(t, s, 555)

	// roll back across the rotation boundary
	r, err := s.RollbackToHeight(context.Background(), &types.MsgRollbackToHeight{Height: 554})
	require.NoError(t, err)
	require.True(t, r.RolledBack)

	// the chain-mirrored interval key reverted: the chain at 554 does not know ss-key-new, and an
	// enclave that still claimed it would be ahead of the chain in exactly the way that cannot
	// converge
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(types.IntervalPublicKeyIDKeyPrefix))
	b := store.Get(types.IntervalPublicKeyIDKey(types.SSNodeID, types.SSNodeType))
	require.NotNil(t, b)
	var current types.IntervalPublicKeyID
	s.Cdc.MustUnmarshal(b, &current)
	require.Equal(t, "ss-key-old", current.PubKID, "the interval key mirror must roll back with the chain")

	// BOTH keys' material survives.  The old one because the chain still references it; the NEW
	// one because the rotation may already have been broadcast -- if the chain rolls forward
	// through 555 again, or a peer encrypted a VShare to ss-key-new, losing privk-new would make
	// that VShare permanently undecryptable.  Key material is cumulative; an unreferenced key is
	// harmless, a missing one is not.
	share, found := s.getShare("ss-key-old")
	require.True(t, found)
	require.Equal(t, "share-old", share)

	share, found = s.getShare("ss-key-new")
	require.True(t, found, "the rotated-in share must survive a rollback -- it cannot be regenerated")
	require.Equal(t, "share-new", share)

	privk, found := s.getPrivKCache("ss-key-new")
	require.True(t, found, "the rotated-in private key must survive a rollback")
	require.Equal(t, "privk-new", privk)
}

// TestRollbackAcrossAMLWindow covers the other half of the split: EnclaveScanTransferHistory is
// SECRET but consensus-critical -- ScanTransaction's verdict decides whether a transfer is
// rejected, so a node holding a different window would reach a different verdict and fork.  It
// therefore stays VERSIONED and must unwind with the transfer that created it, unlike the SS keys
// above.
func TestRollbackAcrossAMLWindow(t *testing.T) {
	s := newTestEnclaveServer(t)

	usd := func(a int64) sdktypes.Coin { return sdktypes.NewInt64Coin("usd", a) }
	qdn := func(a int64) sdktypes.Coin { return sdktypes.NewInt64Coin("aqdn", a) }

	// height 100: one transfer in the window
	s.setScanTransferHistory("sender-1", types.EncryptableScanTransferHistory{
		Transfers: []*types.EncryptableScanTransfer{
			{UnixTime: 1000, DestinationWalletID: "dest-a", USDCoinAmount: usd(4000), CoinAmount: qdn(1)},
		},
	})
	endBlock(t, s, 100)

	// height 101: a second transfer -- together they cross a reporting threshold
	s.setScanTransferHistory("sender-1", types.EncryptableScanTransferHistory{
		Transfers: []*types.EncryptableScanTransfer{
			{UnixTime: 1000, DestinationWalletID: "dest-a", USDCoinAmount: usd(4000), CoinAmount: qdn(1)},
			{UnixTime: 2000, DestinationWalletID: "dest-b", USDCoinAmount: usd(7000), CoinAmount: qdn(2)},
		},
	})
	endBlock(t, s, 101)
	require.Len(t, s.getScanTransferHistory("sender-1").Transfers, 2)

	// unwinding 101 must unwind the transfer's contribution to the window: if it did not, this
	// node would aggregate a movement of value that no longer happened and could reject a later
	// transfer its peers accept
	r, err := s.RollbackToHeight(context.Background(), &types.MsgRollbackToHeight{Height: 100})
	require.NoError(t, err)
	require.True(t, r.RolledBack)

	h := s.getScanTransferHistory("sender-1")
	require.Len(t, h.Transfers, 1, "the AML window must unwind with the transfer that created it")
	require.Equal(t, "dest-a", h.Transfers[0].DestinationWalletID)
}

// TestRollbackReleasesCredentialUniquenessSlot covers the third class: the credential-hash index
// is enclave-private and secret, but it GATES issuance -- a hash left behind by a rolled-back
// credential would block that identity from ever being issued again, bricking it.  So it stays
// versioned too.
func TestRollbackReleasesCredentialUniquenessSlot(t *testing.T) {
	s := newTestEnclaveServer(t)
	endBlock(t, s, 200)

	// height 201 issues a credential and claims its uniqueness slot
	s.setCredentialNoNotify("cred-1", types.PersonalInfoCredentialType, types.Credential{
		CredentialID: "cred-1", CredentialType: types.PersonalInfoCredentialType,
	})
	s.setCredentialByHash("identity-hash-1", "cred-1")
	endBlock(t, s, 201)

	_, found := s.getCredentialByHash("identity-hash-1")
	require.True(t, found, "the slot should be claimed while the credential exists")

	// rolling back must release the slot along with the credential
	r, err := s.RollbackToHeight(context.Background(), &types.MsgRollbackToHeight{Height: 200})
	require.NoError(t, err)
	require.True(t, r.RolledBack)

	_, found = s.getCredentialByHash("identity-hash-1")
	require.False(t, found, "a rolled-back credential must release its uniqueness slot, or the identity is bricked")

	// and the identity can be issued again, as re-execution of 201 would do
	s.setCredentialNoNotify("cred-1", types.PersonalInfoCredentialType, types.Credential{
		CredentialID: "cred-1", CredentialType: types.PersonalInfoCredentialType,
	})
	s.setCredentialByHash("identity-hash-1", "cred-1")
	endBlock(t, s, 201)
	_, found = s.getCredentialByHash("identity-hash-1")
	require.True(t, found)
}

// ---- confidentiality: nothing this branch moved or added may store secrets in the clear ----

// TestSecretTablesAreStillSealed guards against a refactor silently dropping MustSeal /
// MustSealStable.  It matters more than it looks: the enclave's leveldb files live on a hostfs
// mount and are NOT encrypted at rest by anything else -- per-value sealing is the only
// confidentiality those tables have.  Moving the SS tables into a separate DB (enclave_secrets)
// changed WHERE they are written, and this asserts it did not change WHETHER they are sealed.
//
// In simulation mode sealing degrades to prefix concatenation, so "sealed" here means "the bytes
// on disk are not the plaintext" -- enough to catch a dropped seal, which is the regression this
// guards.
func TestSecretTablesAreStillSealed(t *testing.T) {
	s := newTestEnclaveServer(t)

	s.setOwnersAndShare("pubkid-secret", []string{"pioneer1"}, "SHARE-PLAINTEXT-MARKER")
	s.setPrivKCache("pubkid-secret", "PRIVK-PLAINTEXT-MARKER")

	// the raw bytes in the secrets DB must contain neither the plaintext value nor a plaintext key
	rawDump := ""
	it, err := s.SecretsDB.Iterator(nil, nil)
	require.NoError(t, err)
	for ; it.Valid(); it.Next() {
		rawDump += string(it.Key()) + "|" + string(it.Value()) + "\n"
	}
	it.Close()

	// KEYS are stable-sealed, and that IS real even in simulation (MustSealStable is AES-GCM
	// with a fixed nonce, not a prefix), so the bare pubKID must not be readable.
	require.NotContains(t, rawDump, "Enclave/SSIntervalShares/value/pubkid-secret", "the share's key is stored unsealed")
	require.NotContains(t, rawDump, "Enclave/SSIntervalPrivK/value/pubkid-secret", "the privK's key is stored unsealed")

	// VALUES: in simulation MustSeal degrades to prefixing with the signer id, so the plaintext
	// IS readable here -- by design, and the reason a debug enclave must never hold real data.
	// What this test can still prove, and the regression it exists to catch, is that the value
	// went THROUGH MustSeal at all: a dropped seal would store the bare protobuf, with no
	// prefix.  Under --realenclave the same call is ecrypto.SealWithProductKey and the value is
	// genuinely encrypted; that cannot be asserted from a simulation build.
	require.Contains(t, rawDump, signerID+"\n", "the SS share/privK values did not go through MustSeal")

	// and they still read back correctly through the accessors
	share, found := s.getShare("pubkid-secret")
	require.True(t, found)
	require.Equal(t, "SHARE-PLAINTEXT-MARKER", share)
	privk, found := s.getPrivKCache("pubkid-secret")
	require.True(t, found)
	require.Equal(t, "PRIVK-PLAINTEXT-MARKER", privk)

	// the AML window stayed in the versioned store, but it is sealed there and must stay sealed
	s.setScanTransferHistory("sender-secret", types.EncryptableScanTransferHistory{
		Transfers: []*types.EncryptableScanTransfer{
			{UnixTime: 1, DestinationWalletID: "DEST-PLAINTEXT-MARKER"},
		},
	})
	endBlock(t, s, 1)

	treeDump := ""
	tit, err := s.MetaDB.Iterator(nil, nil)
	require.NoError(t, err)
	for ; tit.Valid(); tit.Next() {
		treeDump += string(tit.Value())
	}
	tit.Close()
	// same simulation caveat as above: assert the seal was APPLIED, not that the result is
	// opaque -- only a real SGX build makes it opaque
	require.Contains(t, treeDump, signerID+"\n", "the AML window did not go through MustSeal")
}

// TestOutboxSuspiciousTransactionRoundTrip covers the one genuinely new thing this branch WRITES
// to the store: the outbox.  Two properties at once --
//
//  1. the encrypted-to-the-regulator fields survive the outbox's JSON encoding byte for byte
//     (a silent corruption here would hand the regulator an undecryptable report), and
//  2. nothing in the outbox row is plaintext that was not already public.  The Enc*RegulatorPubK
//     fields are sealed to the regulator before they ever reach this struct; the remaining
//     fields (id, jarID, reason, creator, kinds) are stored on the CHAIN in the clear, so
//     writing them unsealed here leaks nothing that a block explorer does not already show.
func TestOutboxSuspiciousTransactionRoundTrip(t *testing.T) {
	s := newTestEnclaveServer(t)
	endBlock(t, s, 1)

	secret := []byte{0x00, 0xff, 0x10, 0x42, 0xde, 0xad, 0xbe, 0xef}
	st := types.SuspiciousTransaction{
		Id:                                 7,
		JarID:                              "jar1",
		RegulatorPubKID:                    "reg-pubkid",
		Reason:                             "threshold",
		Time:                               time.Unix(1700000000, 0).UTC(),
		EncSourcePersonalInfoRegulatorPubK: secret,
		EncEAmountRegulatorPubK:            secret,
		Creator:                            "qadena1creator",
	}

	s.pendingSuspiciousTransactions = []types.SuspiciousTransaction{st}
	_, err := s.TransactionComplete(context.Background(), &types.MsgTransactionComplete{Success: true})
	require.NoError(t, err)

	got := outboxGet[types.SuspiciousTransaction](s, outboxSuspiciousKey)
	require.Len(t, got, 1)
	require.Equal(t, secret, got[0].EncSourcePersonalInfoRegulatorPubK, "encrypted payload corrupted by the outbox round trip")
	require.Equal(t, secret, got[0].EncEAmountRegulatorPubK)
	require.Equal(t, st.Id, got[0].Id)
	require.Equal(t, st.JarID, got[0].JarID)
	require.True(t, st.Time.Equal(got[0].Time), "timestamp corrupted by the outbox round trip")

	// and it drains to the chain intact
	endBlock(t, s, 2)
	reply, err := s.SyncSuspiciousTransactions(context.Background(), &types.MsgSyncSuspiciousTransactions{Clear: true})
	require.NoError(t, err)
	require.Len(t, reply.SuspiciousTransactions, 1)
	require.Equal(t, secret, reply.SuspiciousTransactions[0].EncSourcePersonalInfoRegulatorPubK)
}
