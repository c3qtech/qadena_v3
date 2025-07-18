package types

import (
	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

var _ sdk.Msg = &MsgRemoveCredential{}

func NewMsgRemoveCredential(creator string, credentialID string, credentialType string) *MsgRemoveCredential {
	return &MsgRemoveCredential{
		Creator:        creator,
		CredentialID:   credentialID,
		CredentialType: credentialType,
	}
}

func (msg *MsgRemoveCredential) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid creator address (%s)", err)
	}
	return nil
}
