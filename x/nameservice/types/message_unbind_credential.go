package types

import (
	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

var _ sdk.Msg = &MsgUnbindCredential{}

func NewMsgUnbindCredential(creator string, credentialType string, credentialInfo string) *MsgUnbindCredential {
	return &MsgUnbindCredential{
		Creator:        creator,
		CredentialType: credentialType,
		CredentialInfo: credentialInfo,
	}
}

func (msg *MsgUnbindCredential) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid creator address (%s)", err)
	}
	if msg.CredentialType == "" {
		return errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "credentialType cannot be empty")
	}
	if msg.CredentialInfo == "" {
		return errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "credentialInfo cannot be empty")
	}
	return nil
}
