package types

import (
	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

var _ sdk.Msg = &MsgPioneerUpdateJarRegulator{}

func NewMsgPioneerUpdateJarRegulator(creator string, jarID string, regulatorID string, remoteReport []byte) *MsgPioneerUpdateJarRegulator {
	return &MsgPioneerUpdateJarRegulator{
		Creator:      creator,
		JarID:        jarID,
		RegulatorID:  regulatorID,
		RemoteReport: remoteReport,
	}
}

func (msg *MsgPioneerUpdateJarRegulator) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid creator address (%s)", err)
	}
	return nil
}
