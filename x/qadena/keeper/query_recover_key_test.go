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

func TestRecoverKeyQuerySingle(t *testing.T) {
	keeper, ctx := keepertest.QadenaKeeper(t)
	msgs := createNRecoverKey(keeper, ctx, 2)
	tests := []struct {
		desc     string
		request  *types.QueryGetRecoverKeyRequest
		response *types.QueryGetRecoverKeyResponse
		err      error
	}{
		{
			desc: "First",
			request: &types.QueryGetRecoverKeyRequest{
				WalletID: msgs[0].WalletID,
			},
			response: &types.QueryGetRecoverKeyResponse{RecoverKey: msgs[0]},
		},
		{
			desc: "Second",
			request: &types.QueryGetRecoverKeyRequest{
				WalletID: msgs[1].WalletID,
			},
			response: &types.QueryGetRecoverKeyResponse{RecoverKey: msgs[1]},
		},
		{
			desc: "KeyNotFound",
			request: &types.QueryGetRecoverKeyRequest{
				WalletID: strconv.Itoa(100000),
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
			response, err := keeper.RecoverKey(ctx, tc.request)
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

func TestRecoverKeyQueryPaginated(t *testing.T) {
	keeper, ctx := keepertest.QadenaKeeper(t)
	msgs := createNRecoverKey(keeper, ctx, 5)

	request := func(next []byte, offset, limit uint64, total bool) *types.QueryAllRecoverKeyRequest {
		return &types.QueryAllRecoverKeyRequest{
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
			resp, err := keeper.RecoverKeyAll(ctx, request(nil, uint64(i), uint64(step), false))
			require.NoError(t, err)
			require.LessOrEqual(t, len(resp.RecoverKey), step)
			require.Subset(t,
				nullify.Fill(msgs),
				nullify.Fill(resp.RecoverKey),
			)
		}
	})
	t.Run("ByKey", func(t *testing.T) {
		step := 2
		var next []byte
		for i := 0; i < len(msgs); i += step {
			resp, err := keeper.RecoverKeyAll(ctx, request(next, 0, uint64(step), false))
			require.NoError(t, err)
			require.LessOrEqual(t, len(resp.RecoverKey), step)
			require.Subset(t,
				nullify.Fill(msgs),
				nullify.Fill(resp.RecoverKey),
			)
			next = resp.Pagination.NextKey
		}
	})
	t.Run("Total", func(t *testing.T) {
		resp, err := keeper.RecoverKeyAll(ctx, request(nil, 0, 0, true))
		require.NoError(t, err)
		require.Equal(t, len(msgs), int(resp.Pagination.Total))
		require.ElementsMatch(t,
			nullify.Fill(msgs),
			nullify.Fill(resp.RecoverKey),
		)
	})
	t.Run("InvalidRequest", func(t *testing.T) {
		_, err := keeper.RecoverKeyAll(ctx, nil)
		require.ErrorIs(t, err, status.Error(codes.InvalidArgument, "invalid request"))
	})
}
