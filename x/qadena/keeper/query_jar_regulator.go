package keeper

import (
	"context"

	"qadena/x/qadena/types"

	"cosmossdk.io/store/prefix"
	"github.com/cosmos/cosmos-sdk/runtime"
	"github.com/cosmos/cosmos-sdk/types/query"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (k Keeper) JarRegulatorAll(ctx context.Context, req *types.QueryAllJarRegulatorRequest) (*types.QueryAllJarRegulatorResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	var jarRegulators []types.JarRegulator

	store := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	jarRegulatorStore := prefix.NewStore(store, types.KeyPrefix(types.JarRegulatorKeyPrefix))

	pageRes, err := query.Paginate(jarRegulatorStore, req.Pagination, func(key []byte, value []byte) error {
		var jarRegulator types.JarRegulator
		if err := k.cdc.Unmarshal(value, &jarRegulator); err != nil {
			return err
		}

		jarRegulators = append(jarRegulators, jarRegulator)
		return nil
	})

	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &types.QueryAllJarRegulatorResponse{JarRegulator: jarRegulators, Pagination: pageRes}, nil
}

func (k Keeper) JarRegulator(ctx context.Context, req *types.QueryGetJarRegulatorRequest) (*types.QueryGetJarRegulatorResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	val, found := k.GetJarRegulator(
		ctx,
		req.JarID,
	)
	if !found {
		return nil, status.Error(codes.NotFound, "not found")
	}

	return &types.QueryGetJarRegulatorResponse{JarRegulator: val}, nil
}
