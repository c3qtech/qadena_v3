package types

import (
	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

var _ sdk.Msg = &MsgClaimCredential{}

func NewMsgClaimCredential(creator string, credentialID string, credentialType string, recoverKey bool, encClaimCredentialExtraParmsVShare []byte, claimCredentialExtraParmsVShareBind *VShareBindData) *MsgClaimCredential {
	return &MsgClaimCredential{
		Creator:                             creator,
		CredentialID:                        credentialID,
		CredentialType:                      credentialType,
		RecoverKey:                          recoverKey,
		EncClaimCredentialExtraParmsVShare:  encClaimCredentialExtraParmsVShare,
		ClaimCredentialExtraParmsVShareBind: claimCredentialExtraParmsVShareBind,
	}
}

func (msg *MsgClaimCredential) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid creator address (%s)", err)
	}
	return nil
}
