package keeper

import (
	"context"

	//errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/c3qtech/qadena_v3/x/qadena/common"

	errorsmod "cosmossdk.io/errors"

	"github.com/c3qtech/qadena_v3/x/qadena/types"
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
		PubKID:   intervalPubKID.PubKID,
		NodeID:   intervalPubKID.NodeID,
		NodeType: intervalPubKID.NodeType,
		// Deactivating means exactly these three things: the type becomes Inactive, and the address
		// and attestation are cleared because the node is no longer reachable or vouched for.
		ServiceProviderType: types.InactiveServiceProvider,
		ExternalIPAddress:   "",
		RemoteReport:        []byte(""),
		// Everything else must survive.  HomePioneerID was being dropped here, and unlike the same
		// defect in the rotation handler this path is live -- it only ever runs on srv-prv records,
		// which are the only kind that carry it.  It is read by GetServiceProviderHomePioneerID,
		// which tx_sign_recover_key.go uses to find the provider's pioneer, so losing it takes key
		// recovery with it.  Deactivation is meant to be reversible; silent data loss is not.
		HomePioneerID: intervalPubKID.HomePioneerID,
	}

	k.Keeper.SetIntervalPublicKeyID(ctx, intervalPublicKeyId)

	return &types.MsgDeactivateServiceProviderResponse{}, nil
}
