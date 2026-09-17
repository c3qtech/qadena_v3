package keeper

import (
	"context"

	"github.com/c3qtech/qadena_v3/x/qadena/types"

	"cosmossdk.io/store/prefix"
	"github.com/cosmos/cosmos-sdk/runtime"
	"github.com/cosmos/cosmos-sdk/types/query"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (k Keeper) ParkedExternalAddressAll(ctx context.Context, req *types.QueryAllParkedExternalAddressRequest) (*types.QueryAllParkedExternalAddressResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	var entries []types.ParkedExternalAddress

	store := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	entryStore := prefix.NewStore(store, types.KeyPrefix(types.ParkedExternalAddressKeyPrefix))

	pageRes, err := query.Paginate(entryStore, req.Pagination, func(key []byte, value []byte) error {
		var entry types.ParkedExternalAddress
		if err := k.cdc.Unmarshal(value, &entry); err != nil {
			return err
		}

		entries = append(entries, entry)
		return nil
	})

	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &types.QueryAllParkedExternalAddressResponse{ParkedExternalAddress: entries, Pagination: pageRes}, nil
}

func (k Keeper) ParkedExternalAddress(ctx context.Context, req *types.QueryGetParkedExternalAddressRequest) (*types.QueryGetParkedExternalAddressResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	val, found := k.GetParkedExternalAddress(ctx, req.PubKID)
	if !found {
		return nil, status.Error(codes.NotFound, "not found")
	}

	return &types.QueryGetParkedExternalAddressResponse{ParkedExternalAddress: val}, nil
}
