package keeper

import (
	"context"

	"qadena_v3/x/qadena/types"

	"cosmossdk.io/store/prefix"
	"github.com/cosmos/cosmos-sdk/runtime"
	"github.com/cosmos/cosmos-sdk/types/query"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (k Keeper) PublicKeyAll(ctx context.Context, req *types.QueryAllPublicKeyRequest) (*types.QueryAllPublicKeyResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	var publicKeys []types.PublicKey

	store := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	publicKeyStore := prefix.NewStore(store, types.KeyPrefix(types.PublicKeyKeyPrefix))

	pageRes, err := query.Paginate(publicKeyStore, req.Pagination, func(key []byte, value []byte) error {
		var publicKey types.PublicKey
		if err := k.cdc.Unmarshal(value, &publicKey); err != nil {
			return err
		}

		publicKeys = append(publicKeys, publicKey)
		return nil
	})

	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &types.QueryAllPublicKeyResponse{PublicKey: publicKeys, Pagination: pageRes}, nil
}

func (k Keeper) PublicKey(ctx context.Context, req *types.QueryGetPublicKeyRequest) (*types.QueryGetPublicKeyResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	val, found := k.GetPublicKey(
		ctx,
		req.PubKID,
		req.PubKType,
	)
	if !found {
		return nil, status.Error(codes.NotFound, "not found")
	}

	return &types.QueryGetPublicKeyResponse{PublicKey: val}, nil
}
