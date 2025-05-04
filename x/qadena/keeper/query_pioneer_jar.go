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

func (k Keeper) PioneerJarAll(ctx context.Context, req *types.QueryAllPioneerJarRequest) (*types.QueryAllPioneerJarResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	var pioneerJars []types.PioneerJar

	store := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	pioneerJarStore := prefix.NewStore(store, types.KeyPrefix(types.PioneerJarKeyPrefix))

	pageRes, err := query.Paginate(pioneerJarStore, req.Pagination, func(key []byte, value []byte) error {
		var pioneerJar types.PioneerJar
		if err := k.cdc.Unmarshal(value, &pioneerJar); err != nil {
			return err
		}

		pioneerJars = append(pioneerJars, pioneerJar)
		return nil
	})

	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &types.QueryAllPioneerJarResponse{PioneerJar: pioneerJars, Pagination: pageRes}, nil
}

func (k Keeper) PioneerJar(ctx context.Context, req *types.QueryGetPioneerJarRequest) (*types.QueryGetPioneerJarResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	val, found := k.GetPioneerJar(
		ctx,
		req.PioneerID,
	)
	if !found {
		return nil, status.Error(codes.NotFound, "not found")
	}

	return &types.QueryGetPioneerJarResponse{PioneerJar: val}, nil
}
