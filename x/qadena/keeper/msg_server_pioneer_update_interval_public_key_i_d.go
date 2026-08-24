package keeper

import (
	"context"

	"github.com/c3qtech/qadena_v3/x/qadena/types"

	"github.com/c3qtech/qadena_v3/x/qadena/common"

	"strings"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// PioneerUpdateIntervalPublicKeyID writes the row that tells every other enclave where to reach a
// node and which interval key it is publishing under.
//
// ATTESTATION IS NOT AUTHORIZATION.  ClientVerifyRemoteReport proves "an enclave whose measurement
// is Active said this string" -- and the sender chooses the string, msg.Creator included.  It
// therefore cannot answer "is this the node that owns the row?", which is the question that
// matters here, because the row's externalIPAddress is what getSSPrivK and the who-has fallback
// DIAL.  Left at attestation alone, any node running a trusted measurement could repoint any other
// pioneer's traffic at a host of its choosing.  That is an eclipse, not key theft -- the redirected
// traffic will not decrypt without the victim's EnclavePrivK -- but it silently removes the victim
// from effective custody while the chain still counts it as an owner.
//
// The check is nearly free because of how these rows are built: for a Pioneer row, Creator and
// PubKID are the SAME bech32 string (updateIsValidator derives both from one GetAddressByName...
// call), and Creator is the message's declared cosmos.msg.v1.signer.  So comparing the stored
// PubKID against Creator IS a possession proof, taken from the ordinary transaction signature --
// no new proto field, no new digest, and replay is already handled by account sequences.
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
		common.ContextInfo(ctx, "PioneerUpdateIntervalPublicKeyID REJECTED "+msg.NodeID+" "+msg.NodeType+" reason=attestation-failed")
		return nil, types.ErrInvalidEnclave
	}

	current, found := k.GetIntervalPublicKeyID(ctx, msg.NodeID, msg.NodeType)
	if found {
		common.ContextDebug(ctx, "...update...")
	} else {
		common.ContextDebug(ctx, "...set... "+msg.NodeID+" "+msg.NodeType+" "+msg.PubKID)
	}

	if msg.NodeType == types.PioneerNodeType {
		// SELF ONLY, ON UPDATE.  The FIRST write stays first-come: before the row exists there is
		// no consensus-safe notion of who owns pioneer N, and registration is separately gated by
		// bonding plus the governance-approved measurement the attestation above just checked.
		if found && current.PubKID != msg.Creator {
			common.ContextInfo(ctx, "PioneerUpdateIntervalPublicKeyID REJECTED "+msg.NodeID+
				" reason=not-row-owner creator="+msg.Creator+" owner="+current.PubKID)
			return nil, types.ErrNotRowOwner
		}
	} else {
		// SS, Jar and Regulator rows have NodeIDs that are constants (types.SSNodeID and friends)
		// with no per-node owner -- they legitimately change every rotation, written by whichever
		// pioneer proposed the block.  So the check is the weaker one tx.proto:58-60 already
		// aspires to ("make sure that the creator IS a Pioneer via enclave"): resolve the creator
		// through the same reverse index AuthenticateServiceProvider uses, and require a Pioneer
		// row.  Safe at bootstrap because InitEnclave broadcasts the Pioneer row earlier in the
		// SAME transaction than the SS/Jar/Regulator ones, and messages apply in order.
		creatorRow, creatorFound := k.GetIntervalPublicKeyIDByPubKID(ctx, msg.Creator)
		if !creatorFound || creatorRow.NodeType != types.PioneerNodeType {
			common.ContextInfo(ctx, "PioneerUpdateIntervalPublicKeyID REJECTED "+msg.NodeID+" "+msg.NodeType+
				" reason=creator-not-pioneer creator="+msg.Creator)
			return nil, types.ErrCreatorNotPioneer
		}
	}

	// AN ABSENT ADDRESS MEANS "NO OPINION", NOT "ERASE IT".
	//
	// Three of the four Pioneer-row producers send an empty ExternalIPAddress -- AddAsValidator
	// (enclave.go:3787) and SyncEnclave (:4960) both do, and only InitEnclave (:3233) and
	// updateIsValidator (:3631) carry one.  SetIntervalPublicKeyID overwrites unconditionally, so
	// without this a re-sync would blank the address of a perfectly healthy pioneer and drop it
	// out of getAddressablePioneers -- shrinking the owner set that getThreshold is computed from.
	externalIPAddress := msg.ExternalIPAddress
	if externalIPAddress == "" && found {
		externalIPAddress = current.ExternalIPAddress
	}

	intervalPublicKeyId := types.IntervalPublicKeyID{
		PubKID:            msg.PubKID,
		NodeID:            msg.NodeID,
		NodeType:          msg.NodeType,
		ExternalIPAddress: externalIPAddress,
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

	// An address MOVE is the event this handler exists to make possible and the one thing a fleet
	// operator will grep for, so say it plainly rather than leaving it to be diffed out of state.
	if found && current.ExternalIPAddress != externalIPAddress {
		common.ContextInfo(ctx, "PioneerUpdateIntervalPublicKeyID address moved "+msg.NodeID+" "+msg.NodeType+
			" from="+current.ExternalIPAddress+" to="+externalIPAddress)
	}

	k.Keeper.SetIntervalPublicKeyID(ctx, intervalPublicKeyId)

	return &types.MsgPioneerUpdateIntervalPublicKeyIDResponse{}, nil
}
