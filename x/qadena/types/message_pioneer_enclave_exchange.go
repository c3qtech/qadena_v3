package types

import (
	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

var _ sdk.Msg = &MsgPioneerEnclaveExchange{}

func NewMsgPioneerEnclaveExchange(creator string, msgType string, msg string) *MsgPioneerEnclaveExchange {
	return &MsgPioneerEnclaveExchange{
		Creator: creator,
		MsgType: msgType,
		Msg:     msg,
	}
}

func (msg *MsgPioneerEnclaveExchange) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid creator address (%s)", err)
	}
	return nil
}
