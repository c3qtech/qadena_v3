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

func TestEnclaveIdentityQuerySingle(t *testing.T) {
	keeper, ctx := keepertest.QadenaKeeper(t)
	msgs := createNEnclaveIdentity(keeper, ctx, 2)
	tests := []struct {
		desc     string
		request  *types.QueryGetEnclaveIdentityRequest
		response *types.QueryGetEnclaveIdentityResponse
		err      error
	}{
		{
			desc: "First",
			request: &types.QueryGetEnclaveIdentityRequest{
				UniqueID: msgs[0].UniqueID,
			},
			response: &types.QueryGetEnclaveIdentityResponse{EnclaveIdentity: msgs[0]},
		},
		{
			desc: "Second",
			request: &types.QueryGetEnclaveIdentityRequest{
				UniqueID: msgs[1].UniqueID,
			},
			response: &types.QueryGetEnclaveIdentityResponse{EnclaveIdentity: msgs[1]},
		},
		{
			desc: "KeyNotFound",
			request: &types.QueryGetEnclaveIdentityRequest{
				UniqueID: strconv.Itoa(100000),
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
			response, err := keeper.EnclaveIdentity(ctx, tc.request)
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

func TestEnclaveIdentityQueryPaginated(t *testing.T) {
	keeper, ctx := keepertest.QadenaKeeper(t)
	msgs := createNEnclaveIdentity(keeper, ctx, 5)

	request := func(next []byte, offset, limit uint64, total bool) *types.QueryAllEnclaveIdentityRequest {
		return &types.QueryAllEnclaveIdentityRequest{
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
			resp, err := keeper.EnclaveIdentityAll(ctx, request(nil, uint64(i), uint64(step), false))
			require.NoError(t, err)
			require.LessOrEqual(t, len(resp.EnclaveIdentity), step)
			require.Subset(t,
				nullify.Fill(msgs),
				nullify.Fill(resp.EnclaveIdentity),
			)
		}
	})
	t.Run("ByKey", func(t *testing.T) {
		step := 2
		var next []byte
		for i := 0; i < len(msgs); i += step {
			resp, err := keeper.EnclaveIdentityAll(ctx, request(next, 0, uint64(step), false))
			require.NoError(t, err)
			require.LessOrEqual(t, len(resp.EnclaveIdentity), step)
			require.Subset(t,
				nullify.Fill(msgs),
				nullify.Fill(resp.EnclaveIdentity),
			)
			next = resp.Pagination.NextKey
		}
	})
	t.Run("Total", func(t *testing.T) {
		resp, err := keeper.EnclaveIdentityAll(ctx, request(nil, 0, 0, true))
		require.NoError(t, err)
		require.Equal(t, len(msgs), int(resp.Pagination.Total))
		require.ElementsMatch(t,
			nullify.Fill(msgs),
			nullify.Fill(resp.EnclaveIdentity),
		)
	})
	t.Run("InvalidRequest", func(t *testing.T) {
		_, err := keeper.EnclaveIdentityAll(ctx, nil)
		require.ErrorIs(t, err, status.Error(codes.InvalidArgument, "invalid request"))
	})
}
