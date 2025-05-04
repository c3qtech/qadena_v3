package keeper_test

import (
	"context"
	"strconv"
	"testing"

	keepertest "qadena/testutil/keeper"
	"qadena/testutil/nullify"
	"qadena/x/qadena/keeper"
	"qadena/x/qadena/types"

	"github.com/stretchr/testify/require"
)

// Prevent strconv unused error
var _ = strconv.IntSize

func createNJarRegulator(keeper keeper.Keeper, ctx context.Context, n int) []types.JarRegulator {
	items := make([]types.JarRegulator, n)
	for i := range items {
		items[i].JarID = strconv.Itoa(i)

		keeper.SetJarRegulator(ctx, items[i])
	}
	return items
}

func TestJarRegulatorGet(t *testing.T) {
	keeper, ctx := keepertest.QadenaKeeper(t)
	items := createNJarRegulator(keeper, ctx, 10)
	for _, item := range items {
		rst, found := keeper.GetJarRegulator(ctx,
			item.JarID,
		)
		require.True(t, found)
		require.Equal(t,
			nullify.Fill(&item),
			nullify.Fill(&rst),
		)
	}
}
func TestJarRegulatorRemove(t *testing.T) {
	keeper, ctx := keepertest.QadenaKeeper(t)
	items := createNJarRegulator(keeper, ctx, 10)
	for _, item := range items {
		keeper.RemoveJarRegulator(ctx,
			item.JarID,
		)
		_, found := keeper.GetJarRegulator(ctx,
			item.JarID,
		)
		require.False(t, found)
	}
}

func TestJarRegulatorGetAll(t *testing.T) {
	keeper, ctx := keepertest.QadenaKeeper(t)
	items := createNJarRegulator(keeper, ctx, 10)
	require.ElementsMatch(t,
		nullify.Fill(items),
		nullify.Fill(keeper.GetAllJarRegulator(ctx)),
	)
}
