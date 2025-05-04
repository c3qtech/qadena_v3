package keeper_test

import (
	"context"
	"strconv"
	"testing"

	keepertest "qadena_v3/testutil/keeper"
	"qadena_v3/testutil/nullify"
	"qadena_v3/x/nameservice/keeper"
	"qadena_v3/x/nameservice/types"

	"github.com/stretchr/testify/require"
)

// Prevent strconv unused error
var _ = strconv.IntSize

func createNNameBinding(keeper keeper.Keeper, ctx context.Context, n int) []types.NameBinding {
	items := make([]types.NameBinding, n)
	for i := range items {
		items[i].Credential = strconv.Itoa(i)
		items[i].CredentialType = strconv.Itoa(i)

		keeper.SetNameBinding(ctx, items[i])
	}
	return items
}

func TestNameBindingGet(t *testing.T) {
	keeper, ctx := keepertest.NameserviceKeeper(t)
	items := createNNameBinding(keeper, ctx, 10)
	for _, item := range items {
		rst, found := keeper.GetNameBinding(ctx,
			item.Credential,
			item.CredentialType,
		)
		require.True(t, found)
		require.Equal(t,
			nullify.Fill(&item),
			nullify.Fill(&rst),
		)
	}
}
func TestNameBindingRemove(t *testing.T) {
	keeper, ctx := keepertest.NameserviceKeeper(t)
	items := createNNameBinding(keeper, ctx, 10)
	for _, item := range items {
		keeper.RemoveNameBinding(ctx,
			item.Credential,
			item.CredentialType,
		)
		_, found := keeper.GetNameBinding(ctx,
			item.Credential,
			item.CredentialType,
		)
		require.False(t, found)
	}
}

func TestNameBindingGetAll(t *testing.T) {
	keeper, ctx := keepertest.NameserviceKeeper(t)
	items := createNNameBinding(keeper, ctx, 10)
	require.ElementsMatch(t,
		nullify.Fill(items),
		nullify.Fill(keeper.GetAllNameBinding(ctx)),
	)
}
