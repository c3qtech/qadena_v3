package types

import (
	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

var _ sdk.Msg = &MsgClaimUpdatedCredential{}

func NewMsgClaimUpdatedCredential(creator string, encAcceptValidatedCredentialsVShare []byte, acceptValidatedCredentialsVShareBind *VShareBindData) *MsgClaimUpdatedCredential {
	return &MsgClaimUpdatedCredential{
		Creator:                              creator,
		EncAcceptValidatedCredentialsVShare:  encAcceptValidatedCredentialsVShare,
		AcceptValidatedCredentialsVShareBind: acceptValidatedCredentialsVShareBind,
	}
}

func (msg *MsgClaimUpdatedCredential) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid creator address (%s)", err)
	}
	if len(msg.EncAcceptValidatedCredentialsVShare) == 0 || msg.AcceptValidatedCredentialsVShareBind == nil {
		return errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "accept validated credentials vshare cannot be empty")
	}
	return nil
}
