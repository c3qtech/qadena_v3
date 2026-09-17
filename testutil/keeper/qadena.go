package keeper

import (
	"testing"

	"cosmossdk.io/log"
	"cosmossdk.io/store"
	"cosmossdk.io/store/metrics"
	storetypes "cosmossdk.io/store/types"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/runtime"
	sdk "github.com/cosmos/cosmos-sdk/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	govtypes "github.com/cosmos/cosmos-sdk/x/gov/types"
	"github.com/stretchr/testify/require"

	"github.com/c3qtech/qadena_v3/x/qadena/keeper"
	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

func QadenaKeeper(t testing.TB) (keeper.Keeper, sdk.Context) {
	return QadenaKeeperWithPricefeed(t, nil)
}

// QadenaKeeperNoParams builds the keeper WITHOUT initializing params, so GetParams reads an empty
// store and returns the proto3 zero value.
//
// That is a real state, not a contrivance: it is what this module's keeper sees while staking's
// InitGenesis bonds the genesis validators, which happens before qadena's InitGenesis has written
// any params -- and it is the state the staking hooks' gate has to read as "off" for a chain to
// bootstrap deterministically.  The ordinary fixture cannot express it, because it sets
// DefaultParams at construction.
func QadenaKeeperNoParams(t testing.TB) (keeper.Keeper, sdk.Context) {
	return buildQadenaKeeper(t, nil, false)
}

// QadenaKeeperWithPricefeed builds the keeper with a caller-supplied pricefeed, so tests can drive
// the fiat conversion into each of its branches.  The keeper's pricefeedKeeper field is unexported,
// so injection has to happen here at construction.
func QadenaKeeperWithPricefeed(t testing.TB, pfk types.PricefeedKeeper) (keeper.Keeper, sdk.Context) {
	return buildQadenaKeeper(t, pfk, true)
}

func buildQadenaKeeper(t testing.TB, pfk types.PricefeedKeeper, initParams bool) (keeper.Keeper, sdk.Context) {
	storeKey := storetypes.NewKVStoreKey(types.StoreKey)

	db := dbm.NewMemDB()
	stateStore := store.NewCommitMultiStore(db, log.NewNopLogger(), metrics.NewNoOpMetrics())
	stateStore.MountStoreWithDB(storeKey, storetypes.StoreTypeIAVL, db)
	require.NoError(t, stateStore.LoadLatestVersion())

	registry := codectypes.NewInterfaceRegistry()
	cdc := codec.NewProtoCodec(registry)
	authority := authtypes.NewModuleAddress(govtypes.ModuleName)

	k := keeper.NewKeeper(
		cdc,
		runtime.NewKVStoreService(storeKey),
		log.NewNopLogger(),
		authority.String(),
		nil,
		nil,
		pfk,
		nil,
		nil,
	)

	ctx := sdk.NewContext(stateStore, cmtproto.Header{}, false, log.NewNopLogger())

	// Initialize params
	if initParams {
		if err := k.SetParams(ctx, types.DefaultParams()); err != nil {
			panic(err)
		}
	}

	return k, ctx
}
