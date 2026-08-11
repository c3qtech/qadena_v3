package main

// The first Go tests in this package.  They exercise the prepare/confirm/rollback state machine
// against in-memory DBs -- nothing SGX-specific is needed: RealEnclave=false degrades sealing to
// prefix concatenation, and MustSealStable only needs a SealedTableSharedSecret to be set.

import (
	"context"
	"testing"

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
