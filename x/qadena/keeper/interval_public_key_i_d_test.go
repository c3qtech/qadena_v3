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

func createNIntervalPublicKeyID(keeper keeper.Keeper, ctx context.Context, n int) []types.IntervalPublicKeyID {
	items := make([]types.IntervalPublicKeyID, n)
	for i := range items {
		items[i].NodeID = strconv.Itoa(i)
		items[i].NodeType = strconv.Itoa(i)

		keeper.SetIntervalPublicKeyID(ctx, items[i])
	}
	return items
}

func TestIntervalPublicKeyIDGet(t *testing.T) {
	keeper, ctx := keepertest.QadenaKeeper(t)
	items := createNIntervalPublicKeyID(keeper, ctx, 10)
	for _, item := range items {
		rst, found := keeper.GetIntervalPublicKeyID(ctx,
			item.NodeID,
			item.NodeType,
		)
		require.True(t, found)
		require.Equal(t,
			nullify.Fill(&item),
			nullify.Fill(&rst),
		)
	}
}
func TestIntervalPublicKeyIDRemove(t *testing.T) {
	keeper, ctx := keepertest.QadenaKeeper(t)
	items := createNIntervalPublicKeyID(keeper, ctx, 10)
	for _, item := range items {
		keeper.RemoveIntervalPublicKeyID(ctx,
			item.NodeID,
			item.NodeType,
		)
		_, found := keeper.GetIntervalPublicKeyID(ctx,
			item.NodeID,
			item.NodeType,
		)
		require.False(t, found)
	}
}

func TestIntervalPublicKeyIDGetAll(t *testing.T) {
	keeper, ctx := keepertest.QadenaKeeper(t)
	items := createNIntervalPublicKeyID(keeper, ctx, 10)
	require.ElementsMatch(t,
		nullify.Fill(items),
		nullify.Fill(keeper.GetAllIntervalPublicKeyID(ctx)),
	)
}
