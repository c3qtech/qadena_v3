package keeper

import (
	"context"

	"github.com/c3qtech/qadena_v3/x/qadena/types"

	"encoding/json"
	"strings"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

func (k msgServer) PioneerBroadcastSecretSharePrivateKey(goCtx context.Context, msg *types.MsgPioneerBroadcastSecretSharePrivateKey) (*types.MsgPioneerBroadcastSecretSharePrivateKeyResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	c.ContextDebug(ctx, "PioneerBroadcastSecretSharePrivateKey")

	keys := ""
	if msg.PrivateKeys != nil {
		b, err := json.Marshal(msg.PrivateKeys)
		if err != nil {
			return nil, err
		}
		keys = string(b)
	}

	if !k.ClientVerifyRemoteReport(ctx, msg.RemoteReport, strings.Join([]string{
		msg.Creator,
		keys,
	}, "|")) {
		return nil, types.ErrInvalidEnclave
	}

	c.ContextDebug(ctx, "PioneerBroadcastSecretSharePrivateKey passed remote report verification")

	for _, key := range msg.PrivateKeys {
		c.ContextDebug(ctx, "PioneerBroadcastSecretSharePrivateKey processing "+c.PrettyPrint(*key))
		if key.PioneerID == k.nodeParams.PioneerID {
			c.ContextDebug(ctx, "PioneerBroadcastSecretSharePrivateKey sending to enclave")
			err := k.EnclaveClientBroadcastSecretSharePrivateKey(ctx, *key) // forward this to the enclave
			if err != nil {
				c.ContextError(ctx, "EnclaveClientBroadcastSecretSharePrivateKey err "+err.Error())
				panic(err.Error())
			}
			break
		}
	}

	return &types.MsgPioneerBroadcastSecretSharePrivateKeyResponse{}, nil
}
