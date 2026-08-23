package keeper

import (
	"context"

	"github.com/c3qtech/qadena_v3/x/qadena/types"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/c3qtech/qadena_v3/x/qadena/common"
)

// PioneerUpdatePublicKey RE-SHARES an existing interval key to a grown owner set.
//
// It is the mirror image of PioneerAddPublicKey and together they keep the existence check as the
// ACL: Add rejects a pubKID that exists, Update rejects one that does not.  Three further gates,
// each closing a specific attack:
//
//	PROPER SUPERSET   the new owner set must strictly contain the stored one.  A re-share can
//	                  therefore never drop an owner (whose enclave would overwrite its held share
//	                  with nothing), never lower the Shamir threshold (getThreshold is monotone in
//	                  owner count), and never apply twice (a replay equals the stored set and
//	                  fails).
//	POSSESSION PROOF  a signature by the interval PRIVATE key over the new shares, verified
//	                  against the STORED row's pubK.  Attestation proves the sender runs trusted
//	                  code; only this proves it holds THIS key -- without it any active enclave
//	                  could rewrite any key's owner set with garbage shares, and the receivers'
//	                  overwrite would destroy the real ones.
//	NO PUBK FIELD     the message cannot carry a public key; the stored row's is inherited.
//	                  RE-SHARE, NOT REKEY, enforced structurally.
func (k msgServer) PioneerUpdatePublicKey(goCtx context.Context, msg *types.MsgPioneerUpdatePublicKey) (*types.MsgPioneerUpdatePublicKeyResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	common.ContextDebug(ctx, "PioneerUpdatePublicKey")

	shares := ""
	if msg.Shares != nil {
		b, err := json.Marshal(msg.Shares)
		if err != nil {
			return nil, err
		}
		shares = string(b)
	}

	// The attested string covers every field, the possession signature included, so a report can
	// neither be replayed from an Add nor re-attached to different shares.
	if !k.ClientVerifyRemoteReport(ctx, msg.RemoteReport, strings.Join([]string{
		msg.Creator,
		msg.PubKID,
		msg.PubKType,
		shares,
		hex.EncodeToString(msg.PossessionSig),
	}, "|")) {
		common.ContextInfo(ctx, "PioneerUpdatePublicKey REJECTED pubKID="+msg.PubKID+" reason=attestation-failed")
		return nil, types.ErrInvalidEnclave
	}

	row, found := k.GetPublicKey(ctx, msg.PubKID, msg.PubKType)
	if !found {
		common.ContextInfo(ctx, "PioneerUpdatePublicKey REJECTED pubKID="+msg.PubKID+" reason=not-found")
		return nil, types.ErrKeyNotFound
	}

	// PROPER SUPERSET.  ValidateBasic already guarantees the new list is duplicate-free.
	oldSet := make(map[string]bool, len(row.Shares))
	for _, share := range row.Shares {
		oldSet[share.PioneerID] = true
	}
	newSet := make(map[string]bool, len(msg.Shares))
	for _, share := range msg.Shares {
		newSet[share.PioneerID] = true
	}
	missing := ""
	for owner := range oldSet {
		if !newSet[owner] {
			missing = owner
			break
		}
	}
	if missing != "" || len(newSet) <= len(oldSet) {
		common.ContextInfo(ctx, "PioneerUpdatePublicKey REJECTED pubKID="+msg.PubKID+
			" reason=not-superset owners "+strconv.Itoa(len(oldSet))+"->"+strconv.Itoa(len(newSet))+
			" dropped="+missing)
		return nil, types.ErrNotOwnerSuperset
	}

	if !common.VerifyPossessionSig(row.PubK, common.PossessionDigest(msg.Creator, msg.PubKID, msg.PubKType, shares), msg.PossessionSig) {
		common.ContextInfo(ctx, "PioneerUpdatePublicKey REJECTED pubKID="+msg.PubKID+" reason=possession-sig-invalid")
		return nil, types.ErrPossessionProofInvalid
	}

	common.ContextInfo(ctx, "PioneerUpdatePublicKey ACCEPTED pubKID="+msg.PubKID+
		" owners "+strconv.Itoa(len(oldSet))+"->"+strconv.Itoa(len(newSet)))

	// PubK inherited from the stored row -- the message has no such field to trust.
	k.Keeper.SetPublicKey(ctx, types.PublicKey{
		PubKID:       msg.PubKID,
		PubK:         row.PubK,
		PubKType:     msg.PubKType,
		RemoteReport: msg.RemoteReport,
		Shares:       msg.Shares,
	})

	return &types.MsgPioneerUpdatePublicKeyResponse{}, nil
}
