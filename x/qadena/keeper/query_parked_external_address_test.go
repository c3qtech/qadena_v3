package keeper_test

import (
	"fmt"
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/query"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	keepertest "github.com/c3qtech/qadena_v3/testutil/keeper"
	"github.com/c3qtech/qadena_v3/testutil/nullify"
	"github.com/c3qtech/qadena_v3/x/qadena/keeper"
	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

func createNParkedExternalAddress(k keeper.Keeper, ctx sdk.Context, n int) []types.ParkedExternalAddress {
	items := make([]types.ParkedExternalAddress, n)
	for i := range items {
		items[i] = types.ParkedExternalAddress{
			PubKID:            fmt.Sprintf("pubkid-%d", i),
			ExternalIPAddress: fmt.Sprintf("10.0.0.%d", i+1),
		}
		k.SetParkedExternalAddress(ctx, items[i])
	}
	return items
}

func TestParkedExternalAddressQuerySingle(t *testing.T) {
	k, ctx := keepertest.QadenaKeeper(t)
	msgs := createNParkedExternalAddress(k, ctx, 2)
	tests := []struct {
		desc     string
		request  *types.QueryGetParkedExternalAddressRequest
		response *types.QueryGetParkedExternalAddressResponse
		err      error
	}{
		{
			desc:     "First",
			request:  &types.QueryGetParkedExternalAddressRequest{PubKID: msgs[0].PubKID},
			response: &types.QueryGetParkedExternalAddressResponse{ParkedExternalAddress: msgs[0]},
		},
		{
			desc:     "Second",
			request:  &types.QueryGetParkedExternalAddressRequest{PubKID: msgs[1].PubKID},
			response: &types.QueryGetParkedExternalAddressResponse{ParkedExternalAddress: msgs[1]},
		},
		{
			desc:    "KeyNotFound",
			request: &types.QueryGetParkedExternalAddressRequest{PubKID: "nothing-parked"},
			err:     status.Error(codes.NotFound, "not found"),
		},
		{
			desc: "InvalidRequest",
			err:  status.Error(codes.InvalidArgument, "invalid request"),
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			response, err := k.ParkedExternalAddress(ctx, tc.request)
			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)
			} else {
				require.NoError(t, err)
				require.Equal(t, nullify.Fill(tc.response), nullify.Fill(response))
			}
		})
	}
}

func TestParkedExternalAddressQueryPaginated(t *testing.T) {
	k, ctx := keepertest.QadenaKeeper(t)
	msgs := createNParkedExternalAddress(k, ctx, 5)

	request := func(next []byte, offset, limit uint64, total bool) *types.QueryAllParkedExternalAddressRequest {
		return &types.QueryAllParkedExternalAddressRequest{
			Pagination: &query.PageRequest{Key: next, Offset: offset, Limit: limit, CountTotal: total},
		}
	}
	t.Run("ByOffset", func(t *testing.T) {
		step := 2
		for i := 0; i < len(msgs); i += step {
			resp, err := k.ParkedExternalAddressAll(ctx, request(nil, uint64(i), uint64(step), false))
			require.NoError(t, err)
			require.LessOrEqual(t, len(resp.ParkedExternalAddress), step)
			require.Subset(t, nullify.Fill(msgs), nullify.Fill(resp.ParkedExternalAddress))
		}
	})
	t.Run("ByKey", func(t *testing.T) {
		step := 2
		var next []byte
		for i := 0; i < len(msgs); i += step {
			resp, err := k.ParkedExternalAddressAll(ctx, request(next, 0, uint64(step), false))
			require.NoError(t, err)
			require.LessOrEqual(t, len(resp.ParkedExternalAddress), step)
			require.Subset(t, nullify.Fill(msgs), nullify.Fill(resp.ParkedExternalAddress))
			next = resp.Pagination.NextKey
		}
	})
	t.Run("Total", func(t *testing.T) {
		resp, err := k.ParkedExternalAddressAll(ctx, request(nil, 0, 0, true))
		require.NoError(t, err)
		require.Equal(t, len(msgs), int(resp.Pagination.Total))
		require.ElementsMatch(t, nullify.Fill(msgs), nullify.Fill(resp.ParkedExternalAddress))
	})
	t.Run("InvalidRequest", func(t *testing.T) {
		_, err := k.ParkedExternalAddressAll(ctx, nil)
		require.ErrorIs(t, err, status.Error(codes.InvalidArgument, "invalid request"))
	})
}

// The query must see exactly what the hooks wrote: park fills it under the operator's ACCOUNT
// address, restore empties it.  This is the path an operator uses to answer "why is this pioneer
// not addressable", so it is tested end to end against the real hooks, not a hand-seeded store.
func TestParkedExternalAddressQueryTracksTheHooks(t *testing.T) {
	k, ctx, h := setupHooks(t)
	setReleaseGate(t, k, ctx, true)
	seedPioneerRow(k, ctx, "10.0.0.1")

	_, err := k.ParkedExternalAddress(ctx, &types.QueryGetParkedExternalAddressRequest{PubKID: testValPubKID()})
	require.ErrorIs(t, err, status.Error(codes.NotFound, "not found"), "nothing parked before an unbond")

	require.NoError(t, h.AfterValidatorBeginUnbonding(ctx, nil, testValAddr))
	resp, err := k.ParkedExternalAddress(ctx, &types.QueryGetParkedExternalAddressRequest{PubKID: testValPubKID()})
	require.NoError(t, err)
	require.Equal(t, "10.0.0.1", resp.ParkedExternalAddress.ExternalIPAddress)

	all, err := k.ParkedExternalAddressAll(ctx, &types.QueryAllParkedExternalAddressRequest{})
	require.NoError(t, err)
	require.Len(t, all.ParkedExternalAddress, 1)

	require.NoError(t, h.AfterValidatorBonded(ctx, nil, testValAddr))
	_, err = k.ParkedExternalAddress(ctx, &types.QueryGetParkedExternalAddressRequest{PubKID: testValPubKID()})
	require.ErrorIs(t, err, status.Error(codes.NotFound, "not found"), "a restore consumes the entry")
}
