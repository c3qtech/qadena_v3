package types

import (
	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

var _ sdk.Msg = &MsgRemoveDocument{}

func NewMsgRemoveDocument(creator string, documentID string) *MsgRemoveDocument {
	return &MsgRemoveDocument{
		Creator:    creator,
		DocumentID: documentID,
	}
}

func (msg *MsgRemoveDocument) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid creator address (%s)", err)
	}
	return nil
}
