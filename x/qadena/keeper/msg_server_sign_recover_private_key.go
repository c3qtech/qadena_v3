package keeper

import (
	"context"

	"github.com/c3qtech/qadena_v3/x/qadena/types"

	sdk "github.com/cosmos/cosmos-sdk/types"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"
)

func (k msgServer) SignRecoverPrivateKey(goCtx context.Context, msg *types.MsgSignRecoverPrivateKey) (*types.MsgSignRecoverPrivateKeyResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	ccPubK := make([]c.VSharePubKInfo, 0)

	ccPubK, err := MsgServerAppendRequiredChainCCPubK(ctx, ccPubK, k.Keeper, "", false)
	if err != nil {
		return nil, err
	}

	if !c.ValidateVShare(ctx, msg.DestinationEWalletIDVShareBind, msg.EncDestinationEWalletIDVShare, ccPubK) {
		return nil, types.ErrInvalidVShare
	}

	// The guardian identity assertion, when present, is bound exactly as the destination wallet id
	// is -- same ccPubK, same check.  Absent is allowed here: individual guardians never send one,
	// and whether an institution's absence is fatal is the enclave's decision, taken from the
	// guardian's class and the chain's assertion mode.  What must NOT happen is a present-but-
	// unbound assertion reaching the enclave, which is what this rejects.
	if msg.GuardianCredentialHashVShareBind != nil {
		if !c.ValidateVShare(ctx, msg.GuardianCredentialHashVShareBind, msg.EncGuardianCredentialHashVShare, ccPubK) {
			return nil, types.ErrInvalidVShare
		}
	}

	// Params are stamped HERE, by the keeper, and travel with the message -- the enclave holds no
	// copy of them and must not take a policy decision from the guardian.  Mirrors
	// msg_server_update_credential.go, which reads them the same way for the same reason.  Reading
	// them per call is also what lets a governance change take effect without restarting nodes.
	err = k.EnclaveClientSignRecoverKey(ctx, *msg, k.GetParams(ctx))

	if err != nil {
		c.ContextError(ctx, "EnclaveClientSignRecoverKey "+err.Error())
		return nil, err
	}

	return &types.MsgSignRecoverPrivateKeyResponse{}, nil
}
