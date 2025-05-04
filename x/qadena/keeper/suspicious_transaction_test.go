package keeper_test

import (
	"context"
	"testing"

	keepertest "qadena/testutil/keeper"
	"qadena/testutil/nullify"
	"qadena/x/qadena/keeper"
	"qadena/x/qadena/types"

	"github.com/stretchr/testify/require"
)

func createNSuspiciousTransaction(keeper keeper.Keeper, ctx context.Context, n int) []types.SuspiciousTransaction {
	items := make([]types.SuspiciousTransaction, n)
	for i := range items {
		items[i].Id = keeper.AppendSuspiciousTransaction(ctx, items[i])
	}
	return items
}

func TestSuspiciousTransactionGet(t *testing.T) {
	keeper, ctx := keepertest.QadenaKeeper(t)
	items := createNSuspiciousTransaction(keeper, ctx, 10)
	for _, item := range items {
		got, found := keeper.GetSuspiciousTransaction(ctx, item.Id)
		require.True(t, found)
		require.Equal(t,
			nullify.Fill(&item),
			nullify.Fill(&got),
		)
	}
}

func TestSuspiciousTransactionRemove(t *testing.T) {
	keeper, ctx := keepertest.QadenaKeeper(t)
	items := createNSuspiciousTransaction(keeper, ctx, 10)
	for _, item := range items {
		keeper.RemoveSuspiciousTransaction(ctx, item.Id)
		_, found := keeper.GetSuspiciousTransaction(ctx, item.Id)
		require.False(t, found)
	}
}

func TestSuspiciousTransactionGetAll(t *testing.T) {
	keeper, ctx := keepertest.QadenaKeeper(t)
	items := createNSuspiciousTransaction(keeper, ctx, 10)
	require.ElementsMatch(t,
		nullify.Fill(items),
		nullify.Fill(keeper.GetAllSuspiciousTransaction(ctx)),
	)
}

func TestSuspiciousTransactionCount(t *testing.T) {
	keeper, ctx := keepertest.QadenaKeeper(t)
	items := createNSuspiciousTransaction(keeper, ctx, 10)
	count := uint64(len(items))
	require.Equal(t, count, keeper.GetSuspiciousTransactionCount(ctx))
}
