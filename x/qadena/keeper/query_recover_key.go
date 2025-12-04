package keeper

import (
	"context"
	"encoding/base64"
	"strconv"
	"time"

	"github.com/c3qtech/qadena_v3/x/qadena/types"

	//	"cosmossdk.io/store/prefix"
	//	"github.com/cosmos/cosmos-sdk/runtime"
	//	"github.com/cosmos/cosmos-sdk/types/query"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

func (k Keeper) RecoverKeyAll(ctx context.Context, req *types.QueryAllRecoverKeyRequest) (*types.QueryAllRecoverKeyResponse, error) {
	return nil, status.Error(codes.Unimplemented, "intentionally mnot implemented")
}

func (k Keeper) RecoverKey(ctx context.Context, req *types.QueryGetRecoverKeyRequest) (*types.QueryGetRecoverKeyResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	// validate timestamp signature
	if req.TimestampSignature == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid timestamp signature")
	}

	// validate timestamp is within a few seconds of now
	if req.Timestamp < time.Now().Unix()-5 || req.Timestamp > time.Now().Unix()+5 {
		return nil, status.Error(codes.InvalidArgument, "invalid timestamp")
	}

	// get the public key of the wallet
	pubk, found := k.GetPublicKey(ctx, req.WalletID, types.TransactionPubKType)
	if !found {
		return nil, status.Error(codes.InvalidArgument, "invalid wallet ID")
	}

	// convert stored PubK (base64-encoded secp256k1) and verify the timestamp signature
	pubBytes, err := base64.StdEncoding.DecodeString(pubk.PubK)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid wallet pubkey encoding: %v", err)
	}
	if len(pubBytes) == 0 {
		return nil, status.Error(codes.InvalidArgument, "empty wallet pubkey")
	}
	pk := secp256k1.PubKey{Key: pubBytes}

	tsBytes := []byte(strconv.FormatInt(req.Timestamp, 10))
	if !pk.VerifySignature(tsBytes, req.TimestampSignature) {
		return nil, status.Error(codes.InvalidArgument, "invalid timestamp signature")
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
