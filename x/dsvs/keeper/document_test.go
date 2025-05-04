package keeper_test

import (
	"context"
	"strconv"
	"testing"

	keepertest "github.com/c3qtech/qadena_v3/testutil/keeper"
	"github.com/c3qtech/qadena_v3/testutil/nullify"
	"github.com/c3qtech/qadena_v3/x/dsvs/keeper"
	"github.com/c3qtech/qadena_v3/x/dsvs/types"

	"github.com/stretchr/testify/require"
)

// Prevent strconv unused error
var _ = strconv.IntSize

func createNDocument(keeper keeper.Keeper, ctx context.Context, n int) []types.Document {
	items := make([]types.Document, n)
	for i := range items {
		items[i].DocumentID = strconv.Itoa(i)

		keeper.SetDocument(ctx, items[i])
	}
	return items
}

func TestDocumentGet(t *testing.T) {
	keeper, ctx := keepertest.DsvsKeeper(t)
	items := createNDocument(keeper, ctx, 10)
	for _, item := range items {
		rst, found := keeper.GetDocument(ctx,
			item.DocumentID,
		)
		require.True(t, found)
		require.Equal(t,
			nullify.Fill(&item),
			nullify.Fill(&rst),
		)
	}
}
func TestDocumentRemove(t *testing.T) {
	keeper, ctx := keepertest.DsvsKeeper(t)
	items := createNDocument(keeper, ctx, 10)
	for _, item := range items {
		keeper.RemoveDocument(ctx,
			item.DocumentID,
		)
		_, found := keeper.GetDocument(ctx,
			item.DocumentID,
		)
		require.False(t, found)
	}
}

func TestDocumentGetAll(t *testing.T) {
	keeper, ctx := keepertest.DsvsKeeper(t)
	items := createNDocument(keeper, ctx, 10)
	require.ElementsMatch(t,
		nullify.Fill(items),
		nullify.Fill(keeper.GetAllDocument(ctx)),
	)
}
