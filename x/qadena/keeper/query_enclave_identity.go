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

func (k Keeper) EnclaveIdentityAll(ctx context.Context, req *types.QueryAllEnclaveIdentityRequest) (*types.QueryAllEnclaveIdentityResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	var enclaveIdentitys []types.EnclaveIdentity

	store := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	enclaveIdentityStore := prefix.NewStore(store, types.KeyPrefix(types.EnclaveIdentityKeyPrefix))

	pageRes, err := query.Paginate(enclaveIdentityStore, req.Pagination, func(key []byte, value []byte) error {
		var enclaveIdentity types.EnclaveIdentity
		if err := k.cdc.Unmarshal(value, &enclaveIdentity); err != nil {
			return err
		}

		enclaveIdentitys = append(enclaveIdentitys, enclaveIdentity)
		return nil
	})

	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &types.QueryAllEnclaveIdentityResponse{EnclaveIdentity: enclaveIdentitys, Pagination: pageRes}, nil
}

func (k Keeper) EnclaveIdentity(ctx context.Context, req *types.QueryGetEnclaveIdentityRequest) (*types.QueryGetEnclaveIdentityResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	val, found := k.GetEnclaveIdentity(
		ctx,
		req.UniqueID,
	)
	if !found {
		return nil, status.Error(codes.NotFound, "not found")
	}

	return &types.QueryGetEnclaveIdentityResponse{EnclaveIdentity: val}, nil
}
