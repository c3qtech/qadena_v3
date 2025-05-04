package types

/*
import (
	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

var _ sdk.Msg = &MsgUpdateIntervalPublicKeyID{}

func NewMsgUpdateIntervalPublicKeyID(creator string, nodeID string, nodeType string, serviceProviderType string) *MsgUpdateIntervalPublicKeyID {
	return &MsgUpdateIntervalPublicKeyID{
		Creator:             creator,
		NodeID:              nodeID,
		NodeType:            nodeType,
		ServiceProviderType: serviceProviderType,
	}
}

func (msg *MsgUpdateIntervalPublicKeyID) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid creator address (%s)", err)
	}
	return nil
}
*/
