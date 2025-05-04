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

func (k Keeper) IntervalPublicKeyIDAll(ctx context.Context, req *types.QueryAllIntervalPublicKeyIDRequest) (*types.QueryAllIntervalPublicKeyIDResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	var intervalPublicKeyIDs []types.IntervalPublicKeyID

	store := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	intervalPublicKeyIDStore := prefix.NewStore(store, types.KeyPrefix(types.IntervalPublicKeyIDKeyPrefix))

	pageRes, err := query.Paginate(intervalPublicKeyIDStore, req.Pagination, func(key []byte, value []byte) error {
		var intervalPublicKeyID types.IntervalPublicKeyID
		if err := k.cdc.Unmarshal(value, &intervalPublicKeyID); err != nil {
			return err
		}

		intervalPublicKeyIDs = append(intervalPublicKeyIDs, intervalPublicKeyID)
		return nil
	})

	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &types.QueryAllIntervalPublicKeyIDResponse{IntervalPublicKeyID: intervalPublicKeyIDs, Pagination: pageRes}, nil
}

func (k Keeper) IntervalPublicKeyID(ctx context.Context, req *types.QueryGetIntervalPublicKeyIDRequest) (*types.QueryGetIntervalPublicKeyIDResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	val, found := k.GetIntervalPublicKeyID(
		ctx,
		req.NodeID,
		req.NodeType,
	)
	if !found {
		return nil, status.Error(codes.NotFound, "not found")
	}

	return &types.QueryGetIntervalPublicKeyIDResponse{IntervalPublicKeyID: val}, nil
}
