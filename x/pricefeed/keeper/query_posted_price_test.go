package keeper_test

import (
	"strconv"
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/query"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	keepertest "qadena_v3/testutil/keeper"
	"qadena_v3/testutil/nullify"
	"qadena_v3/x/pricefeed/types"
)

// Prevent strconv unused error
var _ = strconv.IntSize

func TestPostedPriceQuerySingle(t *testing.T) {
	keeper, ctx := keepertest.PricefeedKeeper(t)
	msgs := createNPostedPrice(keeper, ctx, 2)
	tests := []struct {
		desc     string
		request  *types.QueryGetPostedPriceRequest
		response *types.QueryGetPostedPriceResponse
		err      error
	}{
		{
			desc: "First",
			request: &types.QueryGetPostedPriceRequest{
				MarketId:      msgs[0].MarketId,
				OracleAddress: msgs[0].OracleAddress,
			},
			response: &types.QueryGetPostedPriceResponse{PostedPrice: msgs[0]},
		},
		{
			desc: "Second",
			request: &types.QueryGetPostedPriceRequest{
				MarketId:      msgs[1].MarketId,
				OracleAddress: msgs[1].OracleAddress,
			},
			response: &types.QueryGetPostedPriceResponse{PostedPrice: msgs[1]},
		},
		{
			desc: "KeyNotFound",
			request: &types.QueryGetPostedPriceRequest{
				MarketId:      strconv.Itoa(100000),
				OracleAddress: sdk.AccAddress(strconv.Itoa(100000)),
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
			response, err := keeper.PostedPrice(ctx, tc.request)
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

func TestPostedPriceQueryPaginated(t *testing.T) {
	keeper, ctx := keepertest.PricefeedKeeper(t)
	msgs := createNPostedPrice(keeper, ctx, 5)

	request := func(next []byte, offset, limit uint64, total bool) *types.QueryAllPostedPriceRequest {
		return &types.QueryAllPostedPriceRequest{
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
			resp, err := keeper.PostedPriceAll(ctx, request(nil, uint64(i), uint64(step), false))
			require.NoError(t, err)
			require.LessOrEqual(t, len(resp.PostedPrice), step)
			require.Subset(t,
				nullify.Fill(msgs),
				nullify.Fill(resp.PostedPrice),
			)
		}
	})
	t.Run("ByKey", func(t *testing.T) {
		step := 2
		var next []byte
		for i := 0; i < len(msgs); i += step {
			resp, err := keeper.PostedPriceAll(ctx, request(next, 0, uint64(step), false))
			require.NoError(t, err)
			require.LessOrEqual(t, len(resp.PostedPrice), step)
			require.Subset(t,
				nullify.Fill(msgs),
				nullify.Fill(resp.PostedPrice),
			)
			next = resp.Pagination.NextKey
		}
	})
	t.Run("Total", func(t *testing.T) {
		resp, err := keeper.PostedPriceAll(ctx, request(nil, 0, 0, true))
		require.NoError(t, err)
		require.Equal(t, len(msgs), int(resp.Pagination.Total))
		require.ElementsMatch(t,
			nullify.Fill(msgs),
			nullify.Fill(resp.PostedPrice),
		)
	})
	t.Run("InvalidRequest", func(t *testing.T) {
		_, err := keeper.PostedPriceAll(ctx, nil)
		require.ErrorIs(t, err, status.Error(codes.InvalidArgument, "invalid request"))
	})
}
