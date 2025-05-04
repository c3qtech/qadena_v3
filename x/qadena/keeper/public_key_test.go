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

func createNPublicKey(keeper keeper.Keeper, ctx context.Context, n int) []types.PublicKey {
	items := make([]types.PublicKey, n)
	for i := range items {
		items[i].PubKID = strconv.Itoa(i)
		items[i].PubKType = strconv.Itoa(i)

		keeper.SetPublicKey(ctx, items[i])
	}
	return items
}

func TestPublicKeyGet(t *testing.T) {
	keeper, ctx := keepertest.QadenaKeeper(t)
	items := createNPublicKey(keeper, ctx, 10)
	for _, item := range items {
		rst, found := keeper.GetPublicKey(ctx,
			item.PubKID,
			item.PubKType,
		)
		require.True(t, found)
		require.Equal(t,
			nullify.Fill(&item),
			nullify.Fill(&rst),
		)
	}
}
func TestPublicKeyRemove(t *testing.T) {
	keeper, ctx := keepertest.QadenaKeeper(t)
	items := createNPublicKey(keeper, ctx, 10)
	for _, item := range items {
		keeper.RemovePublicKey(ctx,
			item.PubKID,
			item.PubKType,
		)
		_, found := keeper.GetPublicKey(ctx,
			item.PubKID,
			item.PubKType,
		)
		require.False(t, found)
	}
}

func TestPublicKeyGetAll(t *testing.T) {
	keeper, ctx := keepertest.QadenaKeeper(t)
	items := createNPublicKey(keeper, ctx, 10)
	require.ElementsMatch(t,
		nullify.Fill(items),
		nullify.Fill(keeper.GetAllPublicKey(ctx)),
	)
}
