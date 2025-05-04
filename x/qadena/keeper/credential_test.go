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

func createNCredential(keeper keeper.Keeper, ctx context.Context, n int) []types.Credential {
	items := make([]types.Credential, n)
	for i := range items {
		items[i].CredentialID = strconv.Itoa(i)
		items[i].CredentialType = strconv.Itoa(i)

		keeper.SetCredential(ctx, items[i])
	}
	return items
}

func TestCredentialGet(t *testing.T) {
	keeper, ctx := keepertest.QadenaKeeper(t)
	items := createNCredential(keeper, ctx, 10)
	for _, item := range items {
		rst, found := keeper.GetCredential(ctx,
			item.CredentialID,
			item.CredentialType,
		)
		require.True(t, found)
		require.Equal(t,
			nullify.Fill(&item),
			nullify.Fill(&rst),
		)
	}
}
func TestCredentialRemove(t *testing.T) {
	keeper, ctx := keepertest.QadenaKeeper(t)
	items := createNCredential(keeper, ctx, 10)
	for _, item := range items {
		keeper.RemoveCredential(ctx,
			item.CredentialID,
			item.CredentialType,
		)
		_, found := keeper.GetCredential(ctx,
			item.CredentialID,
			item.CredentialType,
		)
		require.False(t, found)
	}
}

func TestCredentialGetAll(t *testing.T) {
	keeper, ctx := keepertest.QadenaKeeper(t)
	items := createNCredential(keeper, ctx, 10)
	require.ElementsMatch(t,
		nullify.Fill(items),
		nullify.Fill(keeper.GetAllCredential(ctx)),
	)
}
