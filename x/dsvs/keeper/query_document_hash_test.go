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
	"github.com/c3qtech/qadena_v3/x/dsvs/types"
)

// Prevent strconv unused error
var _ = strconv.IntSize

func TestDocumentHashQuerySingle(t *testing.T) {
	keeper, ctx := keepertest.DsvsKeeper(t)
	msgs := createNDocumentHash(keeper, ctx, 2)
	tests := []struct {
		desc     string
		request  *types.QueryGetDocumentHashRequest
		response *types.QueryGetDocumentHashResponse
		err      error
	}{
		{
			desc: "First",
			request: &types.QueryGetDocumentHashRequest{
				Hash: msgs[0].Hash,
			},
			response: &types.QueryGetDocumentHashResponse{DocumentHash: msgs[0]},
		},
		{
			desc: "Second",
			request: &types.QueryGetDocumentHashRequest{
				Hash: msgs[1].Hash,
			},
			response: &types.QueryGetDocumentHashResponse{DocumentHash: msgs[1]},
		},
		{
			desc: "KeyNotFound",
			request: &types.QueryGetDocumentHashRequest{
				Hash: []byte(strconv.Itoa(100000)),
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
			response, err := keeper.DocumentHash(ctx, tc.request)
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

func TestDocumentHashQueryPaginated(t *testing.T) {
	keeper, ctx := keepertest.DsvsKeeper(t)
	msgs := createNDocumentHash(keeper, ctx, 5)

	request := func(next []byte, offset, limit uint64, total bool) *types.QueryAllDocumentHashRequest {
		return &types.QueryAllDocumentHashRequest{
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
			resp, err := keeper.DocumentHashAll(ctx, request(nil, uint64(i), uint64(step), false))
			require.NoError(t, err)
			require.LessOrEqual(t, len(resp.DocumentHash), step)
			require.Subset(t,
				nullify.Fill(msgs),
				nullify.Fill(resp.DocumentHash),
			)
		}
	})
	t.Run("ByKey", func(t *testing.T) {
		step := 2
		var next []byte
		for i := 0; i < len(msgs); i += step {
			resp, err := keeper.DocumentHashAll(ctx, request(next, 0, uint64(step), false))
			require.NoError(t, err)
			require.LessOrEqual(t, len(resp.DocumentHash), step)
			require.Subset(t,
				nullify.Fill(msgs),
				nullify.Fill(resp.DocumentHash),
			)
			next = resp.Pagination.NextKey
		}
	})
	t.Run("Total", func(t *testing.T) {
		resp, err := keeper.DocumentHashAll(ctx, request(nil, 0, 0, true))
		require.NoError(t, err)
		require.Equal(t, len(msgs), int(resp.Pagination.Total))
		require.ElementsMatch(t,
			nullify.Fill(msgs),
			nullify.Fill(resp.DocumentHash),
		)
	})
	t.Run("InvalidRequest", func(t *testing.T) {
		_, err := keeper.DocumentHashAll(ctx, nil)
		require.ErrorIs(t, err, status.Error(codes.InvalidArgument, "invalid request"))
	})
}
