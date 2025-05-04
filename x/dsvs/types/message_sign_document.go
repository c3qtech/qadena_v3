package types

import (
	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

var _ sdk.Msg = &MsgSignDocument{}

func NewMsgSignDocument(creator string, completedSignatory *VShareSignatory, currentHash []byte, hash []byte) *MsgSignDocument {
	return &MsgSignDocument{
		Creator:            creator,
		CompletedSignatory: completedSignatory,
		CurrentHash:        currentHash,
		Hash:               hash,
	}
}

func (msg *MsgSignDocument) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid creator address (%s)", err)
	}
	return nil
}
