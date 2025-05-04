package keeper_test

import (
	"context"
	"strconv"
	"testing"

	keepertest "github.com/c3qtech/qadena_v3/testutil/keeper"
	"github.com/c3qtech/qadena_v3/testutil/nullify"
	"github.com/c3qtech/qadena_v3/x/qadena/keeper"
	"github.com/c3qtech/qadena_v3/x/qadena/types"

	"github.com/stretchr/testify/require"
)

// Prevent strconv unused error
var _ = strconv.IntSize

func createNWallet(keeper keeper.Keeper, ctx context.Context, n int) []types.Wallet {
	items := make([]types.Wallet, n)
	for i := range items {
		items[i].WalletID = strconv.Itoa(i)

		keeper.SetWallet(ctx, items[i])
	}
	return items
}

func TestWalletGet(t *testing.T) {
	keeper, ctx := keepertest.QadenaKeeper(t)
	items := createNWallet(keeper, ctx, 10)
	for _, item := range items {
		rst, found := keeper.GetWallet(ctx,
			item.WalletID,
		)
		require.True(t, found)
		require.Equal(t,
			nullify.Fill(&item),
			nullify.Fill(&rst),
		)
	}
}
func TestWalletRemove(t *testing.T) {
	keeper, ctx := keepertest.QadenaKeeper(t)
	items := createNWallet(keeper, ctx, 10)
	for _, item := range items {
		keeper.RemoveWallet(ctx,
			item.WalletID,
		)
		_, found := keeper.GetWallet(ctx,
			item.WalletID,
		)
		require.False(t, found)
	}
}

func TestWalletGetAll(t *testing.T) {
	keeper, ctx := keepertest.QadenaKeeper(t)
	items := createNWallet(keeper, ctx, 10)
	require.ElementsMatch(t,
		nullify.Fill(items),
		nullify.Fill(keeper.GetAllWallet(ctx)),
	)
}
