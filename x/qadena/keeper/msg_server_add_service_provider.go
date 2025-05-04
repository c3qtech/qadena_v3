package keeper

import (
	"context"

	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/c3qtech/qadena_v3/x/qadena/common"

	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

func (k msgServer) AddServiceProvider(goCtx context.Context, msg *types.MsgAddServiceProvider) (*types.MsgAddServiceProviderResponse, error) {
	if k.GetAuthority() != msg.Authority {
		return nil, errorsmod.Wrapf(types.ErrInvalidSigner, "invalid authority; expected %s, got %s", k.GetAuthority(), msg.Authority)
	}

	ctx := sdk.UnwrapSDKContext(goCtx)

	common.ContextDebug(ctx, "AddServiceProvider")

	_, found := k.GetIntervalPublicKeyID(ctx, msg.NodeID, types.ServiceProviderNodeType)
	if found {
		return nil, types.ErrServiceProviderAlreadyExists
	} else {
		common.ContextDebug(ctx, "...set... "+msg.NodeID+" "+types.ServiceProviderNodeType+" "+msg.PubKID)
	}

	intervalPublicKeyId := types.IntervalPublicKeyID{
		PubKID:              msg.PubKID,
		NodeID:              msg.NodeID,
		NodeType:            types.ServiceProviderNodeType,
		ServiceProviderType: msg.ServiceProviderType,
		ExternalIPAddress:   "",
		RemoteReport:        []byte(""),
	}

	k.Keeper.SetIntervalPublicKeyID(ctx, intervalPublicKeyId)

	return &types.MsgAddServiceProviderResponse{}, nil
}
