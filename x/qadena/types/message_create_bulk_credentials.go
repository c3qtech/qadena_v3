package types

import (
	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

var _ sdk.Msg = &MsgCreateBulkCredentials{}

func NewMsgCreateBulkCredentials(creator string, credentialType string, credentialInfoVShareBind *VShareBindData, credentialHashVShareBind *VShareBindData, eKYCAppWalletID string, bulkCredentials []*BulkCredential) *MsgCreateBulkCredentials {
	return &MsgCreateBulkCredentials{
		Creator:                  creator,
		CredentialType:           credentialType,
		CredentialInfoVShareBind: credentialInfoVShareBind,
		CredentialHashVShareBind: credentialHashVShareBind,
		EKYCAppWalletID:          eKYCAppWalletID,
		BulkCredentials:          bulkCredentials,
	}
}

func (msg *MsgCreateBulkCredentials) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid creator address (%s)", err)
	}
	return nil
}
