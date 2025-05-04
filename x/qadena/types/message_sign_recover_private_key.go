package types

import (
	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

var _ sdk.Msg = &MsgSignRecoverPrivateKey{}

func NewMsgSignRecoverPrivateKey(creator string, encDestinationEWalletIDVShare []byte, destinationEWalletIDVShareBind *VShareBindData, recoverShare *RecoverShare) *MsgSignRecoverPrivateKey {
	return &MsgSignRecoverPrivateKey{
		Creator:                        creator,
		EncDestinationEWalletIDVShare:  encDestinationEWalletIDVShare,
		DestinationEWalletIDVShareBind: destinationEWalletIDVShareBind,
		RecoverShare:                   recoverShare,
	}
}

func (msg *MsgSignRecoverPrivateKey) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid creator address (%s)", err)
	}
	return nil
}
