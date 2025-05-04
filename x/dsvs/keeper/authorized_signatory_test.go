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

func createNAuthorizedSignatory(keeper keeper.Keeper, ctx context.Context, n int) []types.AuthorizedSignatory {
	items := make([]types.AuthorizedSignatory, n)
	for i := range items {
		items[i].WalletID = strconv.Itoa(i)

		keeper.SetAuthorizedSignatory(ctx, items[i])
	}
	return items
}

func TestAuthorizedSignatoryGet(t *testing.T) {
	keeper, ctx := keepertest.DsvsKeeper(t)
	items := createNAuthorizedSignatory(keeper, ctx, 10)
	for _, item := range items {
		rst, found := keeper.GetAuthorizedSignatory(ctx,
			item.WalletID,
		)
		require.True(t, found)
		require.Equal(t,
			nullify.Fill(&item),
			nullify.Fill(&rst),
		)
	}
}
func TestAuthorizedSignatoryRemove(t *testing.T) {
	keeper, ctx := keepertest.DsvsKeeper(t)
	items := createNAuthorizedSignatory(keeper, ctx, 10)
	for _, item := range items {
		keeper.RemoveAuthorizedSignatory(ctx,
			item.WalletID,
		)
		_, found := keeper.GetAuthorizedSignatory(ctx,
			item.WalletID,
		)
		require.False(t, found)
	}
}

func TestAuthorizedSignatoryGetAll(t *testing.T) {
	keeper, ctx := keepertest.DsvsKeeper(t)
	items := createNAuthorizedSignatory(keeper, ctx, 10)
	require.ElementsMatch(t,
		nullify.Fill(items),
		nullify.Fill(keeper.GetAllAuthorizedSignatory(ctx)),
	)
}
