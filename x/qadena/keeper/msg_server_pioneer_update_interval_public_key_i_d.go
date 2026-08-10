package keeper

import (
	"context"

	"github.com/c3qtech/qadena_v3/x/qadena/types"

	"github.com/c3qtech/qadena_v3/x/qadena/common"

	"strings"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

func (k msgServer) PioneerUpdateIntervalPublicKeyID(goCtx context.Context, msg *types.MsgPioneerUpdateIntervalPublicKeyID) (*types.MsgPioneerUpdateIntervalPublicKeyIDResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	common.ContextDebug(ctx, "PioneerUpdateIntervalPublicKeyId")

	if !k.ClientVerifyRemoteReport(ctx, msg.RemoteReport, strings.Join([]string{
		msg.Creator,
		msg.PubKID,
		msg.NodeID,
		msg.NodeType,
		msg.ExternalIPAddress,
	}, "|")) {
		return nil, types.ErrInvalidEnclave
	}

	current, found := k.GetIntervalPublicKeyID(ctx, msg.NodeID, msg.NodeType)
	if found {
		common.ContextDebug(ctx, "...update...")
	} else {
		common.ContextDebug(ctx, "...set... "+msg.NodeID+" "+msg.NodeType+" "+msg.PubKID)
	}

	intervalPublicKeyId := types.IntervalPublicKeyID{
		PubKID:            msg.PubKID,
		NodeID:            msg.NodeID,
		NodeType:          msg.NodeType,
		ExternalIPAddress: msg.ExternalIPAddress,
		RemoteReport:      msg.RemoteReport,
		// Carried over explicitly.  The record was previously rebuilt from the message alone, and
		// the message carries neither of these, so a rotation wiped them.  The existing record was
		// read and then used only for a debug log.
		//
		// Latent rather than live today: the enclave only ever sends this for SS, Pioneer, Jar and
		// Regulator nodes, and only a service provider record populates these two fields.  It stays
		// a loaded gun until something rotates a srv-prv key -- at which point that provider would
		// silently stop being a service provider, because ServiceProviderType is what
		// AppendAuthorizeUser and AuthenticateServiceProvider match on.
		//
		// Named fields, not a blanket "keep whatever was non-empty" merge: DeactivateServiceProvider
		// deliberately overwrites ServiceProviderType, and a generic merge would break it.
		ServiceProviderType: current.ServiceProviderType,
		HomePioneerID:       current.HomePioneerID,
	}

	k.Keeper.SetIntervalPublicKeyID(ctx, intervalPublicKeyId)

	return &types.MsgPioneerUpdateIntervalPublicKeyIDResponse{}, nil
}
