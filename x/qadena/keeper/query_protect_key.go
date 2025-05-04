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

func (k Keeper) ProtectKeyAll(ctx context.Context, req *types.QueryAllProtectKeyRequest) (*types.QueryAllProtectKeyResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	subWalletID := ""
	if req.CredentialID != "" {
		credential, found := k.GetCredential(ctx, req.CredentialID, "personal-info")
		if !found {
			return &types.QueryAllProtectKeyResponse{ProtectKey: nil, Pagination: nil}, nil
		}

		subWalletID = k.EnclaveClientQueryGetSubWalletIDByOriginalWalletID(credential)
	}

	var protectKeys []types.ProtectKey

	store := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	protectKeyStore := prefix.NewStore(store, types.KeyPrefix(types.ProtectKeyKeyPrefix))

	pageRes, err := query.Paginate(protectKeyStore, req.Pagination, func(key []byte, value []byte) error {
		var protectKey types.ProtectKey
		if err := k.cdc.Unmarshal(value, &protectKey); err != nil {
			return err
		}

		if subWalletID != "" {
			if protectKey.WalletID == subWalletID {
				protectKeys = append(protectKeys, protectKey)
			}
		} else {
			protectKeys = append(protectKeys, protectKey)
		}

		return nil
	})

	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &types.QueryAllProtectKeyResponse{ProtectKey: protectKeys, Pagination: pageRes}, nil
}

func (k Keeper) ProtectKey(ctx context.Context, req *types.QueryGetProtectKeyRequest) (*types.QueryGetProtectKeyResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	val, found := k.GetProtectKey(
		ctx,
		req.WalletID,
	)
	if !found {
		return nil, status.Error(codes.NotFound, "not found")
	}

	return &types.QueryGetProtectKeyResponse{ProtectKey: val}, nil
}
