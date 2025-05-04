package keeper_test

import (
	"strconv"
	"testing"

	"github.com/cosmos/cosmos-sdk/types/query"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	keepertest "github.com/c3qtech/qadena_v3/testutil/keeper"
	"github.com/c3qtech/qadena_v3/testutil/nullify"
	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

// Prevent strconv unused error
var _ = strconv.IntSize

func TestJarRegulatorQuerySingle(t *testing.T) {
	keeper, ctx := keepertest.QadenaKeeper(t)
	msgs := createNJarRegulator(keeper, ctx, 2)
	tests := []struct {
		desc     string
		request  *types.QueryGetJarRegulatorRequest
		response *types.QueryGetJarRegulatorResponse
		err      error
	}{
		{
			desc: "First",
			request: &types.QueryGetJarRegulatorRequest{
				JarID: msgs[0].JarID,
			},
			response: &types.QueryGetJarRegulatorResponse{JarRegulator: msgs[0]},
		},
		{
			desc: "Second",
			request: &types.QueryGetJarRegulatorRequest{
				JarID: msgs[1].JarID,
			},
			response: &types.QueryGetJarRegulatorResponse{JarRegulator: msgs[1]},
		},
		{
			desc: "KeyNotFound",
			request: &types.QueryGetJarRegulatorRequest{
				JarID: strconv.Itoa(100000),
			},
			err: status.Error(codes.NotFound, "not found"),
		},
		{
			desc: "InvalidRequest",
			err:  status.Error(codes.InvalidArgument, "invalid request"),
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			response, err := keeper.JarRegulator(ctx, tc.request)
			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)
			} else {
				require.NoError(t, err)
				require.Equal(t,
					nullify.Fill(tc.response),
					nullify.Fill(response),
				)
			}
		})
	}
}

func TestJarRegulatorQueryPaginated(t *testing.T) {
	keeper, ctx := keepertest.QadenaKeeper(t)
	msgs := createNJarRegulator(keeper, ctx, 5)

	request := func(next []byte, offset, limit uint64, total bool) *types.QueryAllJarRegulatorRequest {
		return &types.QueryAllJarRegulatorRequest{
			Pagination: &query.PageRequest{
				Key:        next,
				Offset:     offset,
				Limit:      limit,
				CountTotal: total,
			},
		}
	}
	t.Run("ByOffset", func(t *testing.T) {
		step := 2
		for i := 0; i < len(msgs); i += step {
			resp, err := keeper.JarRegulatorAll(ctx, request(nil, uint64(i), uint64(step), false))
			require.NoError(t, err)
			require.LessOrEqual(t, len(resp.JarRegulator), step)
			require.Subset(t,
				nullify.Fill(msgs),
				nullify.Fill(resp.JarRegulator),
			)
		}
	})
	t.Run("ByKey", func(t *testing.T) {
		step := 2
		var next []byte
		for i := 0; i < len(msgs); i += step {
			resp, err := keeper.JarRegulatorAll(ctx, request(next, 0, uint64(step), false))
			require.NoError(t, err)
			require.LessOrEqual(t, len(resp.JarRegulator), step)
			require.Subset(t,
				nullify.Fill(msgs),
				nullify.Fill(resp.JarRegulator),
			)
			next = resp.Pagination.NextKey
		}
	})
	t.Run("Total", func(t *testing.T) {
		resp, err := keeper.JarRegulatorAll(ctx, request(nil, 0, 0, true))
		require.NoError(t, err)
		require.Equal(t, len(msgs), int(resp.Pagination.Total))
		require.ElementsMatch(t,
			nullify.Fill(msgs),
			nullify.Fill(resp.JarRegulator),
		)
	})
	t.Run("InvalidRequest", func(t *testing.T) {
		_, err := keeper.JarRegulatorAll(ctx, nil)
		require.ErrorIs(t, err, status.Error(codes.InvalidArgument, "invalid request"))
	})
}
