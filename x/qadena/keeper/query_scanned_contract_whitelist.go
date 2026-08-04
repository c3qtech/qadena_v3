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

func (k Keeper) ScannedContractWhitelistAll(ctx context.Context, req *types.QueryAllScannedContractWhitelistRequest) (*types.QueryAllScannedContractWhitelistResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	var entries []types.ScannedContractWhitelist

	store := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	entryStore := prefix.NewStore(store, types.KeyPrefix(types.ScannedContractWhitelistKeyPrefix))

	pageRes, err := query.Paginate(entryStore, req.Pagination, func(key []byte, value []byte) error {
		var entry types.ScannedContractWhitelist
		if err := k.cdc.Unmarshal(value, &entry); err != nil {
			return err
		}

		entries = append(entries, entry)
		return nil
	})

	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &types.QueryAllScannedContractWhitelistResponse{ScannedContractWhitelist: entries, Pagination: pageRes}, nil
}

func (k Keeper) ScannedContractWhitelist(ctx context.Context, req *types.QueryGetScannedContractWhitelistRequest) (*types.QueryGetScannedContractWhitelistResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	val, found := k.GetScannedContractWhitelist(
		ctx,
		req.Address,
	)
	if !found {
		return nil, status.Error(codes.NotFound, "not found")
	}

	return &types.QueryGetScannedContractWhitelistResponse{ScannedContractWhitelist: val}, nil
}
