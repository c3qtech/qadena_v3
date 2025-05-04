package keeper

import (
	"context"

	"github.com/c3qtech/qadena_v3/x/qadena/types"

	"cosmossdk.io/store/prefix"
	"github.com/cosmos/cosmos-sdk/runtime"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/cosmos/cosmos-sdk/types/query"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (k Keeper) SuspiciousTransactionAll(ctx context.Context, req *types.QueryAllSuspiciousTransactionRequest) (*types.QueryAllSuspiciousTransactionResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	var suspiciousTransactions []types.SuspiciousTransaction

	store := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	suspiciousTransactionStore := prefix.NewStore(store, types.KeyPrefix(types.SuspiciousTransactionKey))

	pageRes, err := query.Paginate(suspiciousTransactionStore, req.Pagination, func(key []byte, value []byte) error {
		var suspiciousTransaction types.SuspiciousTransaction
		if err := k.cdc.Unmarshal(value, &suspiciousTransaction); err != nil {
			return err
		}

		suspiciousTransactions = append(suspiciousTransactions, suspiciousTransaction)
		return nil
	})

	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &types.QueryAllSuspiciousTransactionResponse{SuspiciousTransaction: suspiciousTransactions, Pagination: pageRes}, nil
}

func (k Keeper) SuspiciousTransaction(ctx context.Context, req *types.QueryGetSuspiciousTransactionRequest) (*types.QueryGetSuspiciousTransactionResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	suspiciousTransaction, found := k.GetSuspiciousTransaction(ctx, req.Id)
	if !found {
		return nil, sdkerrors.ErrKeyNotFound
	}

	return &types.QueryGetSuspiciousTransactionResponse{SuspiciousTransaction: suspiciousTransaction}, nil
}
