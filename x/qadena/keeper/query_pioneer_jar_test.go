package keeper_test

import (
	"strconv"
	"testing"

	"github.com/cosmos/cosmos-sdk/types/query"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	keepertest "qadena/testutil/keeper"
	"qadena/testutil/nullify"
	"qadena/x/qadena/types"
)

// Prevent strconv unused error
var _ = strconv.IntSize

func TestPioneerJarQuerySingle(t *testing.T) {
	keeper, ctx := keepertest.QadenaKeeper(t)
	msgs := createNPioneerJar(keeper, ctx, 2)
	tests := []struct {
		desc     string
		request  *types.QueryGetPioneerJarRequest
		response *types.QueryGetPioneerJarResponse
		err      error
	}{
		{
			desc: "First",
			request: &types.QueryGetPioneerJarRequest{
				PioneerID: msgs[0].PioneerID,
			},
			response: &types.QueryGetPioneerJarResponse{PioneerJar: msgs[0]},
		},
		{
			desc: "Second",
			request: &types.QueryGetPioneerJarRequest{
				PioneerID: msgs[1].PioneerID,
			},
			response: &types.QueryGetPioneerJarResponse{PioneerJar: msgs[1]},
		},
		{
			desc: "KeyNotFound",
			request: &types.QueryGetPioneerJarRequest{
				PioneerID: strconv.Itoa(100000),
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
			response, err := keeper.PioneerJar(ctx, tc.request)
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

func TestPioneerJarQueryPaginated(t *testing.T) {
	keeper, ctx := keepertest.QadenaKeeper(t)
	msgs := createNPioneerJar(keeper, ctx, 5)

	request := func(next []byte, offset, limit uint64, total bool) *types.QueryAllPioneerJarRequest {
		return &types.QueryAllPioneerJarRequest{
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
			resp, err := keeper.PioneerJarAll(ctx, request(nil, uint64(i), uint64(step), false))
			require.NoError(t, err)
			require.LessOrEqual(t, len(resp.PioneerJar), step)
			require.Subset(t,
				nullify.Fill(msgs),
				nullify.Fill(resp.PioneerJar),
			)
		}
	})
	t.Run("ByKey", func(t *testing.T) {
		step := 2
		var next []byte
		for i := 0; i < len(msgs); i += step {
			resp, err := keeper.PioneerJarAll(ctx, request(next, 0, uint64(step), false))
			require.NoError(t, err)
			require.LessOrEqual(t, len(resp.PioneerJar), step)
			require.Subset(t,
				nullify.Fill(msgs),
				nullify.Fill(resp.PioneerJar),
			)
			next = resp.Pagination.NextKey
		}
	})
	t.Run("Total", func(t *testing.T) {
		resp, err := keeper.PioneerJarAll(ctx, request(nil, 0, 0, true))
		require.NoError(t, err)
		require.Equal(t, len(msgs), int(resp.Pagination.Total))
		require.ElementsMatch(t,
			nullify.Fill(msgs),
			nullify.Fill(resp.PioneerJar),
		)
	})
	t.Run("InvalidRequest", func(t *testing.T) {
		_, err := keeper.PioneerJarAll(ctx, nil)
		require.ErrorIs(t, err, status.Error(codes.InvalidArgument, "invalid request"))
	})
}
