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

func TestIntervalPublicKeyIDQuerySingle(t *testing.T) {
	keeper, ctx := keepertest.QadenaKeeper(t)
	msgs := createNIntervalPublicKeyID(keeper, ctx, 2)
	tests := []struct {
		desc     string
		request  *types.QueryGetIntervalPublicKeyIDRequest
		response *types.QueryGetIntervalPublicKeyIDResponse
		err      error
	}{
		{
			desc: "First",
			request: &types.QueryGetIntervalPublicKeyIDRequest{
				NodeID:   msgs[0].NodeID,
				NodeType: msgs[0].NodeType,
			},
			response: &types.QueryGetIntervalPublicKeyIDResponse{IntervalPublicKeyID: msgs[0]},
		},
		{
			desc: "Second",
			request: &types.QueryGetIntervalPublicKeyIDRequest{
				NodeID:   msgs[1].NodeID,
				NodeType: msgs[1].NodeType,
			},
			response: &types.QueryGetIntervalPublicKeyIDResponse{IntervalPublicKeyID: msgs[1]},
		},
		{
			desc: "KeyNotFound",
			request: &types.QueryGetIntervalPublicKeyIDRequest{
				NodeID:   strconv.Itoa(100000),
				NodeType: strconv.Itoa(100000),
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
			response, err := keeper.IntervalPublicKeyID(ctx, tc.request)
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

func TestIntervalPublicKeyIDQueryPaginated(t *testing.T) {
	keeper, ctx := keepertest.QadenaKeeper(t)
	msgs := createNIntervalPublicKeyID(keeper, ctx, 5)

	request := func(next []byte, offset, limit uint64, total bool) *types.QueryAllIntervalPublicKeyIDRequest {
		return &types.QueryAllIntervalPublicKeyIDRequest{
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
			resp, err := keeper.IntervalPublicKeyIDAll(ctx, request(nil, uint64(i), uint64(step), false))
			require.NoError(t, err)
			require.LessOrEqual(t, len(resp.IntervalPublicKeyID), step)
			require.Subset(t,
				nullify.Fill(msgs),
				nullify.Fill(resp.IntervalPublicKeyID),
			)
		}
	})
	t.Run("ByKey", func(t *testing.T) {
		step := 2
		var next []byte
		for i := 0; i < len(msgs); i += step {
			resp, err := keeper.IntervalPublicKeyIDAll(ctx, request(next, 0, uint64(step), false))
			require.NoError(t, err)
			require.LessOrEqual(t, len(resp.IntervalPublicKeyID), step)
			require.Subset(t,
				nullify.Fill(msgs),
				nullify.Fill(resp.IntervalPublicKeyID),
			)
			next = resp.Pagination.NextKey
		}
	})
	t.Run("Total", func(t *testing.T) {
		resp, err := keeper.IntervalPublicKeyIDAll(ctx, request(nil, 0, 0, true))
		require.NoError(t, err)
		require.Equal(t, len(msgs), int(resp.Pagination.Total))
		require.ElementsMatch(t,
			nullify.Fill(msgs),
			nullify.Fill(resp.IntervalPublicKeyID),
		)
	})
	t.Run("InvalidRequest", func(t *testing.T) {
		_, err := keeper.IntervalPublicKeyIDAll(ctx, nil)
		require.ErrorIs(t, err, status.Error(codes.InvalidArgument, "invalid request"))
	})
}
