package keeper

import (
	"context"

	//errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"qadena/x/qadena/common"

	errorsmod "cosmossdk.io/errors"

	"qadena/x/qadena/types"
)

func (k msgServer) DeactivateServiceProvider(goCtx context.Context, msg *types.MsgDeactivateServiceProvider) (*types.MsgDeactivateServiceProviderResponse, error) {
	if k.GetAuthority() != msg.Authority {
		return nil, errorsmod.Wrapf(types.ErrInvalidSigner, "invalid authority; expected %s, got %s", k.GetAuthority(), msg.Authority)
	}

	ctx := sdk.UnwrapSDKContext(goCtx)

	intervalPubKID, found := k.Keeper.GetIntervalPublicKeyID(ctx, msg.NodeID, types.ServiceProviderNodeType)

	if !found {
		return nil, types.ErrServiceProviderNotFound
	}

	common.ContextDebug(ctx, "DeactivateServiceProvider", msg.NodeID)

	intervalPublicKeyId := types.IntervalPublicKeyID{
		PubKID:              intervalPubKID.PubKID,
		NodeID:              intervalPubKID.NodeID,
		NodeType:            intervalPubKID.NodeType,
		ServiceProviderType: types.InactiveServiceProvider,
		ExternalIPAddress:   "",
		RemoteReport:        []byte(""),
	}

	k.Keeper.SetIntervalPublicKeyID(ctx, intervalPublicKeyId)

	return &types.MsgDeactivateServiceProviderResponse{}, nil
}
