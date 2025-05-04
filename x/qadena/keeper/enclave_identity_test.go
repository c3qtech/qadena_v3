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

func createNEnclaveIdentity(keeper keeper.Keeper, ctx context.Context, n int) []types.EnclaveIdentity {
	items := make([]types.EnclaveIdentity, n)
	for i := range items {
		items[i].UniqueID = strconv.Itoa(i)

		keeper.SetEnclaveIdentity(ctx, items[i])
	}
	return items
}

func TestEnclaveIdentityGet(t *testing.T) {
	keeper, ctx := keepertest.QadenaKeeper(t)
	items := createNEnclaveIdentity(keeper, ctx, 10)
	for _, item := range items {
		rst, found := keeper.GetEnclaveIdentity(ctx,
			item.UniqueID,
		)
		require.True(t, found)
		require.Equal(t,
			nullify.Fill(&item),
			nullify.Fill(&rst),
		)
	}
}
func TestEnclaveIdentityRemove(t *testing.T) {
	keeper, ctx := keepertest.QadenaKeeper(t)
	items := createNEnclaveIdentity(keeper, ctx, 10)
	for _, item := range items {
		keeper.RemoveEnclaveIdentity(ctx,
			item.UniqueID,
		)
		_, found := keeper.GetEnclaveIdentity(ctx,
			item.UniqueID,
		)
		require.False(t, found)
	}
}

func TestEnclaveIdentityGetAll(t *testing.T) {
	keeper, ctx := keepertest.QadenaKeeper(t)
	items := createNEnclaveIdentity(keeper, ctx, 10)
	require.ElementsMatch(t,
		nullify.Fill(items),
		nullify.Fill(keeper.GetAllEnclaveIdentity(ctx)),
	)
}
