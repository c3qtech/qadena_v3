package types

import (
	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

var _ sdk.Msg = &MsgAddPublicKey{}

func NewMsgAddPublicKey(creator string, pubK string, pubKType string) *MsgAddPublicKey {
	return &MsgAddPublicKey{
		Creator:  creator,
		PubK:     pubK,
		PubKType: pubKType,
	}
}

func (msg *MsgAddPublicKey) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid creator address (%s)", err)
	}
	return nil
}
