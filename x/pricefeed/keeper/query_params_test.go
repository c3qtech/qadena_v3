package keeper_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	keepertest "github.com/c3qtech/qadena_v3/testutil/keeper"
	"github.com/c3qtech/qadena_v3/x/pricefeed/types"
)

func TestParamsQuery(t *testing.T) {
	keeper, ctx := keepertest.PricefeedKeeper(t)
	params := types.DefaultParams()
	require.NoError(t, keeper.SetParams(ctx, params))

	response, err := keeper.Params(ctx, &types.QueryParamsRequest{})
	require.NoError(t, err)
	require.Equal(t, &types.QueryParamsResponse{Params: params}, response)
}
