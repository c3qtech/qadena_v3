package types

import (
	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

var _ sdk.Msg = &MsgPioneerUpdatePioneerJar{}

func NewMsgPioneerUpdatePioneerJar(creator string, pioneerID string, jarID string, remoteReport []byte) *MsgPioneerUpdatePioneerJar {
	return &MsgPioneerUpdatePioneerJar{
		Creator:      creator,
		PioneerID:    pioneerID,
		JarID:        jarID,
		RemoteReport: remoteReport,
	}
}

func (msg *MsgPioneerUpdatePioneerJar) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid creator address (%s)", err)
	}
	return nil
}
