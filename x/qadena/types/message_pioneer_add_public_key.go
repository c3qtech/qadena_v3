package types

import (
	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

var _ sdk.Msg = &MsgPioneerAddPublicKey{}

func NewMsgPioneerAddPublicKey(creator string, pubKID string, pubK string, pubKType string, shares []*Share, remoteReport []byte) *MsgPioneerAddPublicKey {
	return &MsgPioneerAddPublicKey{
		Creator:      creator,
		PubKID:       pubKID,
		PubK:         pubK,
		PubKType:     pubKType,
		Shares:       shares,
		RemoteReport: remoteReport,
	}
}

func (msg *MsgPioneerAddPublicKey) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid creator address (%s)", err)
	}
	return nil
}
