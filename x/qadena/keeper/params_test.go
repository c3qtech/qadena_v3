package keeper_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	keepertest "qadena_v3/testutil/keeper"
	"qadena_v3/x/qadena/types"
)

func TestGetParams(t *testing.T) {
	k, ctx := keepertest.QadenaKeeper(t)
	params := types.DefaultParams()

	require.NoError(t, k.SetParams(ctx, params))
	require.EqualValues(t, params, k.GetParams(ctx))
}
