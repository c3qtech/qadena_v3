package keeper_test

import (
	"testing"

	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/cosmos/cosmos-sdk/types/query"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	keepertest "qadena_v3/testutil/keeper"
	"qadena_v3/testutil/nullify"
	"qadena_v3/x/qadena/types"
)

func TestSuspiciousTransactionQuerySingle(t *testing.T) {
	keeper, ctx := keepertest.QadenaKeeper(t)
	msgs := createNSuspiciousTransaction(keeper, ctx, 2)
	tests := []struct {
		desc     string
		request  *types.QueryGetSuspiciousTransactionRequest
		response *types.QueryGetSuspiciousTransactionResponse
		err      error
	}{
		{
			desc:     "First",
			request:  &types.QueryGetSuspiciousTransactionRequest{Id: msgs[0].Id},
			response: &types.QueryGetSuspiciousTransactionResponse{SuspiciousTransaction: msgs[0]},
		},
		{
			desc:     "Second",
			request:  &types.QueryGetSuspiciousTransactionRequest{Id: msgs[1].Id},
			response: &types.QueryGetSuspiciousTransactionResponse{SuspiciousTransaction: msgs[1]},
		},
		{
			desc:    "KeyNotFound",
			request: &types.QueryGetSuspiciousTransactionRequest{Id: uint64(len(msgs))},
			err:     sdkerrors.ErrKeyNotFound,
		},
		{
			desc: "InvalidRequest",
			err:  status.Error(codes.InvalidArgument, "invalid request"),
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			response, err := keeper.SuspiciousTransaction(ctx, tc.request)
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

func TestSuspiciousTransactionQueryPaginated(t *testing.T) {
	keeper, ctx := keepertest.QadenaKeeper(t)
	msgs := createNSuspiciousTransaction(keeper, ctx, 5)

	request := func(next []byte, offset, limit uint64, total bool) *types.QueryAllSuspiciousTransactionRequest {
		return &types.QueryAllSuspiciousTransactionRequest{
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
			resp, err := keeper.SuspiciousTransactionAll(ctx, request(nil, uint64(i), uint64(step), false))
			require.NoError(t, err)
			require.LessOrEqual(t, len(resp.SuspiciousTransaction), step)
			require.Subset(t,
				nullify.Fill(msgs),
				nullify.Fill(resp.SuspiciousTransaction),
			)
		}
	})
	t.Run("ByKey", func(t *testing.T) {
		step := 2
		var next []byte
		for i := 0; i < len(msgs); i += step {
			resp, err := keeper.SuspiciousTransactionAll(ctx, request(next, 0, uint64(step), false))
			require.NoError(t, err)
			require.LessOrEqual(t, len(resp.SuspiciousTransaction), step)
			require.Subset(t,
				nullify.Fill(msgs),
				nullify.Fill(resp.SuspiciousTransaction),
			)
			next = resp.Pagination.NextKey
		}
	})
	t.Run("Total", func(t *testing.T) {
		resp, err := keeper.SuspiciousTransactionAll(ctx, request(nil, 0, 0, true))
		require.NoError(t, err)
		require.Equal(t, len(msgs), int(resp.Pagination.Total))
		require.ElementsMatch(t,
			nullify.Fill(msgs),
			nullify.Fill(resp.SuspiciousTransaction),
		)
	})
	t.Run("InvalidRequest", func(t *testing.T) {
		_, err := keeper.SuspiciousTransactionAll(ctx, nil)
		require.ErrorIs(t, err, status.Error(codes.InvalidArgument, "invalid request"))
	})
}
