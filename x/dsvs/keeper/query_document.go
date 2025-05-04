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

func (k Keeper) DocumentAll(ctx context.Context, req *types.QueryAllDocumentRequest) (*types.QueryAllDocumentResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	var documents []types.Document

	store := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	documentStore := prefix.NewStore(store, types.KeyPrefix(types.DocumentKeyPrefix))

	pageRes, err := query.Paginate(documentStore, req.Pagination, func(key []byte, value []byte) error {
		var document types.Document
		if err := k.cdc.Unmarshal(value, &document); err != nil {
			return err
		}

		documents = append(documents, document)
		return nil
	})

	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &types.QueryAllDocumentResponse{Document: documents, Pagination: pageRes}, nil
}

func (k Keeper) Document(ctx context.Context, req *types.QueryGetDocumentRequest) (*types.QueryGetDocumentResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	val, found := k.GetDocument(
		ctx,
		req.DocumentID,
	)
	if !found {
		return nil, status.Error(codes.NotFound, "not found")
	}

	return &types.QueryGetDocumentResponse{Document: val}, nil
}
