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

func createNDocumentHash(keeper keeper.Keeper, ctx context.Context, n int) []types.DocumentHash {
	items := make([]types.DocumentHash, n)
	for i := range items {
		items[i].Hash = []byte(strconv.Itoa(i))

		keeper.SetDocumentHash(ctx, items[i])
	}
	return items
}

func TestDocumentHashGet(t *testing.T) {
	keeper, ctx := keepertest.DsvsKeeper(t)
	items := createNDocumentHash(keeper, ctx, 10)
	for _, item := range items {
		rst, found := keeper.GetDocumentHash(ctx,
			item.Hash,
		)
		require.True(t, found)
		require.Equal(t,
			nullify.Fill(&item),
			nullify.Fill(&rst),
		)
	}
}
func TestDocumentHashRemove(t *testing.T) {
	keeper, ctx := keepertest.DsvsKeeper(t)
	items := createNDocumentHash(keeper, ctx, 10)
	for _, item := range items {
		keeper.RemoveDocumentHash(ctx,
			item.Hash,
		)
		_, found := keeper.GetDocumentHash(ctx,
			item.Hash,
		)
		require.False(t, found)
	}
}

func TestDocumentHashGetAll(t *testing.T) {
	keeper, ctx := keepertest.DsvsKeeper(t)
	items := createNDocumentHash(keeper, ctx, 10)
	require.ElementsMatch(t,
		nullify.Fill(items),
		nullify.Fill(keeper.GetAllDocumentHash(ctx)),
	)
}
