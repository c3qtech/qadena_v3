package types

import (
	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

var _ sdk.Msg = &MsgCreateCredential{}

func NewMsgCreateCredential(creator string, credentialID string, credentialType string, credentialPedersenCommit *BPedersenCommit, credentialInfoVShareBind *VShareBindData, encCredentialInfoVShare []byte, credentialHashVShareBind *VShareBindData, encCredentialHashVShare []byte, findCredentialPedersenCommit *BPedersenCommit, eKYCAppWalletID string, referenceCredentialID string) *MsgCreateCredential {
	return &MsgCreateCredential{
		Creator:                      creator,
		CredentialID:                 credentialID,
		CredentialType:               credentialType,
		CredentialPedersenCommit:     credentialPedersenCommit,
		CredentialInfoVShareBind:     credentialInfoVShareBind,
		EncCredentialInfoVShare:      encCredentialInfoVShare,
		CredentialHashVShareBind:     credentialHashVShareBind,
		EncCredentialHashVShare:      encCredentialHashVShare,
		FindCredentialPedersenCommit: findCredentialPedersenCommit,
		EKYCAppWalletID:              eKYCAppWalletID,
		ReferenceCredentialID:        referenceCredentialID,
	}
}

func (msg *MsgCreateCredential) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid creator address (%s)", err)
	}
	return nil
}
