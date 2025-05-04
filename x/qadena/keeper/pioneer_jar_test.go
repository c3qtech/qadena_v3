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

func createNPioneerJar(keeper keeper.Keeper, ctx context.Context, n int) []types.PioneerJar {
	items := make([]types.PioneerJar, n)
	for i := range items {
		items[i].PioneerID = strconv.Itoa(i)

		keeper.SetPioneerJar(ctx, items[i])
	}
	return items
}

func TestPioneerJarGet(t *testing.T) {
	keeper, ctx := keepertest.QadenaKeeper(t)
	items := createNPioneerJar(keeper, ctx, 10)
	for _, item := range items {
		rst, found := keeper.GetPioneerJar(ctx,
			item.PioneerID,
		)
		require.True(t, found)
		require.Equal(t,
			nullify.Fill(&item),
			nullify.Fill(&rst),
		)
	}
}
func TestPioneerJarRemove(t *testing.T) {
	keeper, ctx := keepertest.QadenaKeeper(t)
	items := createNPioneerJar(keeper, ctx, 10)
	for _, item := range items {
		keeper.RemovePioneerJar(ctx,
			item.PioneerID,
		)
		_, found := keeper.GetPioneerJar(ctx,
			item.PioneerID,
		)
		require.False(t, found)
	}
}

func TestPioneerJarGetAll(t *testing.T) {
	keeper, ctx := keepertest.QadenaKeeper(t)
	items := createNPioneerJar(keeper, ctx, 10)
	require.ElementsMatch(t,
		nullify.Fill(items),
		nullify.Fill(keeper.GetAllPioneerJar(ctx)),
	)
}
