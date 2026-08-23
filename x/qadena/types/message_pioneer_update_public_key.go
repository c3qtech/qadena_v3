package types

import (
	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

var _ sdk.Msg = &MsgPioneerUpdatePublicKey{}

func NewMsgPioneerUpdatePublicKey(creator string, pubKID string, pubKType string, shares []*Share, possessionSig []byte, remoteReport []byte) *MsgPioneerUpdatePublicKey {
	return &MsgPioneerUpdatePublicKey{
		Creator:       creator,
		PubKID:        pubKID,
		PubKType:      pubKType,
		Shares:        shares,
		PossessionSig: possessionSig,
		RemoteReport:  remoteReport,
	}
}

// Bounds that keep a hostile message cheap to reject.  MaxReshareShares is deliberately far above
// maxSSShareSplits (20) so the wire format never has to move in lockstep with the enclave's cap;
// MaxReshareShareBytes bounds one encrypted share blob (161 bytes measured on the wire, so 1 KiB
// is generous); the possession signature is DER ECDSA, which is 70-72 bytes in practice.
const (
	MaxReshareShares     = 64
	MaxReshareShareBytes = 1024
	MinPossessionSigLen  = 8
	MaxPossessionSigLen  = 96
)

func (msg *MsgPioneerUpdatePublicKey) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid creator address (%s)", err)
	}
	if msg.PubKID == "" {
		return errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "pubKID is required")
	}
	if len(msg.Shares) == 0 || len(msg.Shares) > MaxReshareShares {
		return errorsmod.Wrapf(sdkerrors.ErrInvalidRequest, "a re-share must carry between 1 and %d shares, got %d", MaxReshareShares, len(msg.Shares))
	}
	// A REPEATED OWNER IS A REPEATED SHAMIR X-COORDINATE: shamir.Combine has no integrity check,
	// so a duplicate silently weakens the threshold.  Rejected here so no handler needs to re-check.
	seen := make(map[string]bool, len(msg.Shares))
	for _, share := range msg.Shares {
		if share == nil || share.PioneerID == "" {
			return errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "every share must name its owner pioneer")
		}
		if seen[share.PioneerID] {
			return errorsmod.Wrapf(sdkerrors.ErrInvalidRequest, "duplicate owner %s (a duplicate Shamir x-coordinate)", share.PioneerID)
		}
		seen[share.PioneerID] = true
		if len(share.EncEnclaveShare) == 0 || len(share.EncEnclaveShare) > MaxReshareShareBytes {
			return errorsmod.Wrapf(sdkerrors.ErrInvalidRequest, "share for %s must be 1..%d bytes", share.PioneerID, MaxReshareShareBytes)
		}
	}
	if len(msg.PossessionSig) < MinPossessionSigLen || len(msg.PossessionSig) > MaxPossessionSigLen {
		return errorsmod.Wrapf(sdkerrors.ErrInvalidRequest, "possession signature must be %d..%d bytes", MinPossessionSigLen, MaxPossessionSigLen)
	}
	return nil
}
