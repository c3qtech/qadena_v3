package types

import (
	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

var _ sdk.Msg = &MsgSignRecoverPrivateKey{}

// NewMsgSignRecoverPrivateKey builds a guardian's signature message.
//
// The guardian-credential-hash pair is OPTIONAL and may be (nil, nil): individual guardians never
// send it, and institutional ones did not before the assertion existed.  Whether an absent
// assertion is fatal is decided by the enclave, from the guardian's class and the chain's
// sign_recover_key_guardian_assertion_mode -- neither of which is visible from here.
func NewMsgSignRecoverPrivateKey(creator string, encDestinationEWalletIDVShare []byte, destinationEWalletIDVShareBind *VShareBindData, recoverShare *RecoverShare, encGuardianCredentialHashVShare []byte, guardianCredentialHashVShareBind *VShareBindData) *MsgSignRecoverPrivateKey {
	return &MsgSignRecoverPrivateKey{
		Creator:                          creator,
		EncDestinationEWalletIDVShare:    encDestinationEWalletIDVShare,
		DestinationEWalletIDVShareBind:   destinationEWalletIDVShareBind,
		RecoverShare:                     recoverShare,
		EncGuardianCredentialHashVShare:  encGuardianCredentialHashVShare,
		GuardianCredentialHashVShareBind: guardianCredentialHashVShareBind,
	}
}

// ValidateBasic checks only what is checkable without state.
//
// The guardian assertion is deliberately NOT required here.  Whether it must be present depends on
// the guardian's class (institutions are held to it, individuals are exempt) and on a chain param,
// and ValidateBasic can see neither -- it runs with no store and no context.  Rejecting an absent
// assertion here would also make the field mandatory the moment it shipped, which is exactly what
// the audit mode exists to avoid.
func (msg *MsgSignRecoverPrivateKey) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid creator address (%s)", err)
	}
	return nil
}
