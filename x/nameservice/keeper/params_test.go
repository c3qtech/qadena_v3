package keeper_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	keepertest "qadena/testutil/keeper"
	"qadena/x/nameservice/types"
)

func TestGetParams(t *testing.T) {
	k, ctx := keepertest.NameserviceKeeper(t)
	params := types.DefaultParams()

	require.NoError(t, k.SetParams(ctx, params))
	require.EqualValues(t, params, k.GetParams(ctx))
}
