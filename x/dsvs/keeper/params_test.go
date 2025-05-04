package keeper_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	keepertest "github.com/c3qtech/qadena_v3/testutil/keeper"
	"github.com/c3qtech/qadena_v3/x/dsvs/types"
)

func TestGetParams(t *testing.T) {
	k, ctx := keepertest.DsvsKeeper(t)
	params := types.DefaultParams()

	require.NoError(t, k.SetParams(ctx, params))
	require.EqualValues(t, params, k.GetParams(ctx))
}
