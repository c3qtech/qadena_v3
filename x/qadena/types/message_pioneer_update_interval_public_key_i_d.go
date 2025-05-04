package types

import (
	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

var _ sdk.Msg = &MsgPioneerUpdateIntervalPublicKeyID{}

func NewMsgPioneerUpdateIntervalPublicKeyID(creator string, pubKID string, nodeID string, nodeType string, externalIPAddress string, remoteReport []byte) *MsgPioneerUpdateIntervalPublicKeyID {
	return &MsgPioneerUpdateIntervalPublicKeyID{
		Creator:           creator,
		PubKID:            pubKID,
		NodeID:            nodeID,
		NodeType:          nodeType,
		ExternalIPAddress: externalIPAddress,
		RemoteReport:      remoteReport,
	}
}

func (msg *MsgPioneerUpdateIntervalPublicKeyID) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid creator address (%s)", err)
	}
	return nil
}
