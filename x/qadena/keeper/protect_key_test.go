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

func createNProtectKey(keeper keeper.Keeper, ctx context.Context, n int) []types.ProtectKey {
	items := make([]types.ProtectKey, n)
	for i := range items {
		items[i].WalletID = strconv.Itoa(i)

		keeper.SetProtectKey(ctx, items[i])
	}
	return items
}

func TestProtectKeyGet(t *testing.T) {
	keeper, ctx := keepertest.QadenaKeeper(t)
	items := createNProtectKey(keeper, ctx, 10)
	for _, item := range items {
		rst, found := keeper.GetProtectKey(ctx,
			item.WalletID,
		)
		require.True(t, found)
		require.Equal(t,
			nullify.Fill(&item),
			nullify.Fill(&rst),
		)
	}
}
func TestProtectKeyRemove(t *testing.T) {
	keeper, ctx := keepertest.QadenaKeeper(t)
	items := createNProtectKey(keeper, ctx, 10)
	for _, item := range items {
		keeper.RemoveProtectKey(ctx,
			item.WalletID,
		)
		_, found := keeper.GetProtectKey(ctx,
			item.WalletID,
		)
		require.False(t, found)
	}
}

func TestProtectKeyGetAll(t *testing.T) {
	keeper, ctx := keepertest.QadenaKeeper(t)
	items := createNProtectKey(keeper, ctx, 10)
	require.ElementsMatch(t,
		nullify.Fill(items),
		nullify.Fill(keeper.GetAllProtectKey(ctx)),
	)
}
