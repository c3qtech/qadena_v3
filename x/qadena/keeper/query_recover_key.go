package keeper

import (
	"context"

	"qadena_v3/x/qadena/types"

	"cosmossdk.io/store/prefix"
	"github.com/cosmos/cosmos-sdk/runtime"
	"github.com/cosmos/cosmos-sdk/types/query"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

func (k Keeper) RecoverKeyAll(ctx context.Context, req *types.QueryAllRecoverKeyRequest) (*types.QueryAllRecoverKeyResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	subWalletID := ""
	if req.CredentialID != "" {
		credential, found := k.GetCredential(ctx, req.CredentialID, "personal-info")
		if !found {
			return &types.QueryAllRecoverKeyResponse{RecoverKey: nil, Pagination: nil}, nil
		}

		subWalletID = k.EnclaveClientQueryGetSubWalletIDByOriginalWalletID(credential)
	}

	var recoverKeys []types.RecoverKey

	store := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	recoverKeyStore := prefix.NewStore(store, types.KeyPrefix(types.RecoverKeyKeyPrefix))

	pageRes, err := query.Paginate(recoverKeyStore, req.Pagination, func(key []byte, value []byte) error {
		var recoverKey types.RecoverKey
		if err := k.cdc.Unmarshal(value, &recoverKey); err != nil {
			return err
		}

		if subWalletID != "" {
			if recoverKey.WalletID == subWalletID {
				recoverKeys = append(recoverKeys, recoverKey)
			}
		} else {
			recoverKeys = append(recoverKeys, recoverKey)
		}

		return nil
	})

	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &types.QueryAllRecoverKeyResponse{RecoverKey: recoverKeys, Pagination: pageRes}, nil
}

func (k Keeper) RecoverKey(ctx context.Context, req *types.QueryGetRecoverKeyRequest) (*types.QueryGetRecoverKeyResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	sdkctx := sdk.UnwrapSDKContext(ctx)

	err, val := k.EnclaveQueryGetRecoverKey(sdkctx,
		req,
	)
	if err != nil {
		return nil, err
	}

	return val, nil
}
