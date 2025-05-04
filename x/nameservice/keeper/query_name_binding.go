package keeper

import (
	"context"

	"github.com/c3qtech/qadena_v3/x/nameservice/types"

	"cosmossdk.io/store/prefix"
	"github.com/cosmos/cosmos-sdk/runtime"
	"github.com/cosmos/cosmos-sdk/types/query"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (k Keeper) NameBindingAll(ctx context.Context, req *types.QueryAllNameBindingRequest) (*types.QueryAllNameBindingResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	var nameBindings []types.NameBinding

	store := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	nameBindingStore := prefix.NewStore(store, types.KeyPrefix(types.NameBindingKeyPrefix))

	pageRes, err := query.Paginate(nameBindingStore, req.Pagination, func(key []byte, value []byte) error {
		var nameBinding types.NameBinding
		if err := k.cdc.Unmarshal(value, &nameBinding); err != nil {
			return err
		}

		nameBindings = append(nameBindings, nameBinding)
		return nil
	})

	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &types.QueryAllNameBindingResponse{NameBinding: nameBindings, Pagination: pageRes}, nil
}

func (k Keeper) NameBinding(ctx context.Context, req *types.QueryGetNameBindingRequest) (*types.QueryGetNameBindingResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	val, found := k.GetNameBinding(
		ctx,
		req.Credential,
		req.CredentialType,
	)
	if !found {
		return nil, status.Error(codes.NotFound, "not found")
	}

	return &types.QueryGetNameBindingResponse{NameBinding: val}, nil
}
