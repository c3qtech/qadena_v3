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

func (k Keeper) WalletAll(ctx context.Context, req *types.QueryAllWalletRequest) (*types.QueryAllWalletResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	var wallets []types.Wallet

	store := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	walletStore := prefix.NewStore(store, types.KeyPrefix(types.WalletKeyPrefix))

	pageRes, err := query.Paginate(walletStore, req.Pagination, func(key []byte, value []byte) error {
		var wallet types.Wallet
		if err := k.cdc.Unmarshal(value, &wallet); err != nil {
			return err
		}

		wallets = append(wallets, wallet)
		return nil
	})

	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &types.QueryAllWalletResponse{Wallet: wallets, Pagination: pageRes}, nil
}

func (k Keeper) Wallet(ctx context.Context, req *types.QueryGetWalletRequest) (*types.QueryGetWalletResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	val, found := k.GetWallet(
		ctx,
		req.WalletID,
	)
	if !found {
		return nil, status.Error(codes.NotFound, "not found")
	}

	return &types.QueryGetWalletResponse{Wallet: val}, nil
}
