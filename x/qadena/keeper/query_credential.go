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

func (k Keeper) CredentialAll(ctx context.Context, req *types.QueryAllCredentialRequest) (*types.QueryAllCredentialResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	var credentials []types.Credential

	store := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	credentialStore := prefix.NewStore(store, types.KeyPrefix(types.CredentialKeyPrefix))

	pageRes, err := query.Paginate(credentialStore, req.Pagination, func(key []byte, value []byte) error {
		var credential types.Credential
		if err := k.cdc.Unmarshal(value, &credential); err != nil {
			return err
		}

		credentials = append(credentials, credential)
		return nil
	})

	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &types.QueryAllCredentialResponse{Credential: credentials, Pagination: pageRes}, nil
}

func (k Keeper) Credential(ctx context.Context, req *types.QueryGetCredentialRequest) (*types.QueryGetCredentialResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	val, found := k.GetCredential(
		ctx,
		req.CredentialID,
		req.CredentialType,
	)
	if !found {
		return nil, status.Error(codes.NotFound, "not found")
	}

	return &types.QueryGetCredentialResponse{Credential: val}, nil
}
