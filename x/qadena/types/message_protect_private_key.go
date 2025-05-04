package types

import (
	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

var _ sdk.Msg = &MsgProtectPrivateKey{}

func NewMsgProtectPrivateKey(creator string, threshold int32, recoverShare []*RecoverShare) *MsgProtectPrivateKey {
	return &MsgProtectPrivateKey{
		Creator:      creator,
		Threshold:    threshold,
		RecoverShare: recoverShare,
	}
}

func (msg *MsgProtectPrivateKey) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid creator address (%s)", err)
	}
	return nil
}
