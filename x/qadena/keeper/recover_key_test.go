package keeper_test

import (
	"context"
	"strconv"
	"testing"

	keepertest "qadena_v3/testutil/keeper"
	"qadena_v3/testutil/nullify"
	"qadena_v3/x/qadena/keeper"
	"qadena_v3/x/qadena/types"

	"github.com/stretchr/testify/require"
)

// Prevent strconv unused error
var _ = strconv.IntSize

func createNRecoverKey(keeper keeper.Keeper, ctx context.Context, n int) []types.RecoverKey {
	items := make([]types.RecoverKey, n)
	for i := range items {
		items[i].WalletID = strconv.Itoa(i)

		keeper.SetRecoverKey(ctx, items[i])
	}
	return items
}

func TestRecoverKeyGet(t *testing.T) {
	keeper, ctx := keepertest.QadenaKeeper(t)
	items := createNRecoverKey(keeper, ctx, 10)
	for _, item := range items {
		rst, found := keeper.GetRecoverKey(ctx,
			item.WalletID,
		)
		require.True(t, found)
		require.Equal(t,
			nullify.Fill(&item),
			nullify.Fill(&rst),
		)
	}
}
func TestRecoverKeyRemove(t *testing.T) {
	keeper, ctx := keepertest.QadenaKeeper(t)
	items := createNRecoverKey(keeper, ctx, 10)
	for _, item := range items {
		keeper.RemoveRecoverKey(ctx,
			item.WalletID,
		)
		_, found := keeper.GetRecoverKey(ctx,
			item.WalletID,
		)
		require.False(t, found)
	}
}

func TestRecoverKeyGetAll(t *testing.T) {
	keeper, ctx := keepertest.QadenaKeeper(t)
	items := createNRecoverKey(keeper, ctx, 10)
	require.ElementsMatch(t,
		nullify.Fill(items),
		nullify.Fill(keeper.GetAllRecoverKey(ctx)),
	)
}
