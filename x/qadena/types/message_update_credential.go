package types

import (
	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

var _ sdk.Msg = &MsgUpdateCredential{}

func NewMsgUpdateCredential(creator string, credentialID string, credentialType string, encUpdateCredentialExtraParmsVShare []byte, updateCredentialExtraParmsVShareBind *VShareBindData) *MsgUpdateCredential {
	return &MsgUpdateCredential{
		Creator:                              creator,
		CredentialID:                         credentialID,
		CredentialType:                       credentialType,
		EncUpdateCredentialExtraParmsVShare:  encUpdateCredentialExtraParmsVShare,
		UpdateCredentialExtraParmsVShareBind: updateCredentialExtraParmsVShareBind,
	}
}

func (msg *MsgUpdateCredential) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid creator address (%s)", err)
	}
	if msg.CredentialID == "" {
		return errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "credentialID cannot be empty")
	}
	if msg.CredentialType == "" {
		return errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "credentialType cannot be empty")
	}
	return nil
}
