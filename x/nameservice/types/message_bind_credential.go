package types

import (
	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

var _ sdk.Msg = &MsgBindCredential{}

func NewMsgBindCredential(creator string, credentialType string, credentialInfo string, credentialPedersenCommit *BPedersenCommit) *MsgBindCredential {
	return &MsgBindCredential{
		Creator:                  creator,
		CredentialType:           credentialType,
		CredentialInfo:           credentialInfo,
		CredentialPedersenCommit: credentialPedersenCommit,
	}
}

func (msg *MsgBindCredential) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid creator address (%s)", err)
	}
	return nil
}
