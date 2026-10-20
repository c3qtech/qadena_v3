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
//	ELIGIBLE OWNERS   every stored owner that has NOT departed must still be present.  An owner
//	                  may be dropped only if PioneerHasDeparted says so -- parked out of the
//	                  bonded set for longer than Params.SsDepartureGrace.  This replaces the
//	                  PROPER SUPERSET rule, which could never drop anyone and so left a departed
//	                  pioneer owning every key it ever held, forever, with the audit counting it
//	                  as live custody.
//	GENERATION CAS    the message names the generation it expects to replace.  The superset rule
//	                  used to double as the replay guard for free (a replay named the stored set
//	                  and failed strictness); once a shrink is legal that stops working, and a
//	                  stale re-share would revert the owner list AND install shares from a split
//	                  that no longer matches the key.  See PublicKey.generation.
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
	// THE EXPECTED GENERATION IS PART OF THE ATTESTED STRING.  Without it the CAS value would be
	// the one field of this message an intermediary could edit: re-pointing a valid re-share at a
	// different generation, which is precisely the ordering attack the CAS exists to stop.
	if !k.ClientVerifyRemoteReport(ctx, msg.RemoteReport, strings.Join([]string{
		msg.Creator,
		msg.PubKID,
		msg.PubKType,
		shares,
		hex.EncodeToString(msg.PossessionSig),
		strconv.FormatUint(msg.ExpectedGeneration, 10),
	}, "|")) {
		common.ContextInfo(ctx, "PioneerUpdatePublicKey REJECTED pubKID="+msg.PubKID+" reason=attestation-failed")
		return nil, types.ErrInvalidEnclave
	}

	row, found := k.GetPublicKey(ctx, msg.PubKID, msg.PubKType)
	if !found {
		common.ContextInfo(ctx, "PioneerUpdatePublicKey REJECTED pubKID="+msg.PubKID+" reason=not-found")
		return nil, types.ErrKeyNotFound
	}

	// GENERATION CAS, BEFORE ANYTHING ELSE IS JUDGED.  A stale message must be refused on being
	// stale, not on whatever its owner set happens to look like against a row it was never
	// computed from -- that would report a confusing reason for the right rejection.
	if msg.ExpectedGeneration != row.Generation {
		common.ContextInfo(ctx, "PioneerUpdatePublicKey REJECTED pubKID="+msg.PubKID+
			" reason=stale-generation expected="+strconv.FormatUint(msg.ExpectedGeneration, 10)+
			" stored="+strconv.FormatUint(row.Generation, 10))
		return nil, types.ErrStaleGeneration
	}

	// ELIGIBLE OWNERS.  ValidateBasic already guarantees the new list is duplicate-free.
	oldSet := make(map[string]bool, len(row.Shares))
	for _, share := range row.Shares {
		oldSet[share.PioneerID] = true
	}
	newSet := make(map[string]bool, len(msg.Shares))
	for _, share := range msg.Shares {
		newSet[share.PioneerID] = true
	}
	// A dropped owner is allowed only if the CHAIN says it departed.  Liveness is deliberately not
	// consulted: an owner's departure decides whose shares are valid, so it must be a fact every
	// node derives identically at this height, or nodes disagree about the owner set and fork.
	stillEligible := ""
	for owner := range oldSet {
		if newSet[owner] {
			continue
		}
		if !k.PioneerHasDeparted(ctx, owner) {
			stillEligible = owner
			break
		}
	}
	if stillEligible != "" {
		common.ContextInfo(ctx, "PioneerUpdatePublicKey REJECTED pubKID="+msg.PubKID+
			" reason=owner-still-eligible owners "+strconv.Itoa(len(oldSet))+"->"+strconv.Itoa(len(newSet))+
			" dropped="+stillEligible)
		return nil, types.ErrOwnerStillEligible
	}
	// AND IT MUST STILL BE A RE-SHARE.  Dropping every owner, or emptying the set, is not a
	// custody change this message is allowed to express -- it would leave a key on the chain that
	// nobody is recorded as holding.
	if len(newSet) == 0 {
		common.ContextInfo(ctx, "PioneerUpdatePublicKey REJECTED pubKID="+msg.PubKID+" reason=empty-owner-set")
		return nil, types.ErrOwnerStillEligible
	}

	if !common.VerifyPossessionSig(row.PubK, common.PossessionDigest(msg.Creator, msg.PubKID, msg.PubKType, shares), msg.PossessionSig) {
		common.ContextInfo(ctx, "PioneerUpdatePublicKey REJECTED pubKID="+msg.PubKID+" reason=possession-sig-invalid")
		return nil, types.ErrPossessionProofInvalid
	}

	common.ContextInfo(ctx, "PioneerUpdatePublicKey ACCEPTED pubKID="+msg.PubKID+
		" owners "+strconv.Itoa(len(oldSet))+"->"+strconv.Itoa(len(newSet))+
		" generation "+strconv.FormatUint(row.Generation, 10)+"->"+strconv.FormatUint(row.Generation+1, 10))

	// PubK inherited from the stored row -- the message has no such field to trust.  Generation is
	// likewise derived from the row, never taken from the message: the message only says which
	// generation it EXPECTED, and letting it name the next one would hand an attacker the ability
	// to skip ahead and strand every re-share computed against the real sequence.
	k.Keeper.SetPublicKey(ctx, types.PublicKey{
		PubKID:       msg.PubKID,
		PubK:         row.PubK,
		PubKType:     msg.PubKType,
		RemoteReport: msg.RemoteReport,
		Shares:       msg.Shares,
		Generation:   row.Generation + 1,
	})

	return &types.MsgPioneerUpdatePublicKeyResponse{}, nil
}
