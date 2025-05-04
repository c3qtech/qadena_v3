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

func (k Keeper) DocumentHashAll(ctx context.Context, req *types.QueryAllDocumentHashRequest) (*types.QueryAllDocumentHashResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	var documentHashs []types.DocumentHash

	store := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	documentHashStore := prefix.NewStore(store, types.KeyPrefix(types.DocumentHashKeyPrefix))

	pageRes, err := query.Paginate(documentHashStore, req.Pagination, func(key []byte, value []byte) error {
		var documentHash types.DocumentHash
		if err := k.cdc.Unmarshal(value, &documentHash); err != nil {
			return err
		}

		documentHashs = append(documentHashs, documentHash)
		return nil
	})

	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &types.QueryAllDocumentHashResponse{DocumentHash: documentHashs, Pagination: pageRes}, nil
}

func (k Keeper) DocumentHash(ctx context.Context, req *types.QueryGetDocumentHashRequest) (*types.QueryGetDocumentHashResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	val, found := k.GetDocumentHash(
		ctx,
		req.Hash,
	)
	if !found {
		return nil, status.Error(codes.NotFound, "not found")
	}

	return &types.QueryGetDocumentHashResponse{DocumentHash: val}, nil
}
