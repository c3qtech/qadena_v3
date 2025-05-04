package keeper

import (
	"context"

	"github.com/c3qtech/qadena_v3/x/dsvs/types"

	"cosmossdk.io/store/prefix"
	"github.com/cosmos/cosmos-sdk/runtime"
	"github.com/cosmos/cosmos-sdk/types/query"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (k Keeper) AuthorizedSignatoryAll(ctx context.Context, req *types.QueryAllAuthorizedSignatoryRequest) (*types.QueryAllAuthorizedSignatoryResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	var authorizedSignatorys []types.AuthorizedSignatory

	store := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	authorizedSignatoryStore := prefix.NewStore(store, types.KeyPrefix(types.AuthorizedSignatoryKeyPrefix))

	pageRes, err := query.Paginate(authorizedSignatoryStore, req.Pagination, func(key []byte, value []byte) error {
		var authorizedSignatory types.AuthorizedSignatory
		if err := k.cdc.Unmarshal(value, &authorizedSignatory); err != nil {
			return err
		}

		authorizedSignatorys = append(authorizedSignatorys, authorizedSignatory)
		return nil
	})

	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &types.QueryAllAuthorizedSignatoryResponse{AuthorizedSignatory: authorizedSignatorys, Pagination: pageRes}, nil
}

func (k Keeper) AuthorizedSignatory(ctx context.Context, req *types.QueryGetAuthorizedSignatoryRequest) (*types.QueryGetAuthorizedSignatoryResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	val, found := k.GetAuthorizedSignatory(
		ctx,
		req.WalletID,
	)
	if !found {
		return nil, status.Error(codes.NotFound, "not found")
	}

	return &types.QueryGetAuthorizedSignatoryResponse{AuthorizedSignatory: val}, nil
}
