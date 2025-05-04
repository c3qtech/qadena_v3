package types

import (
	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

var _ sdk.Msg = &MsgPioneerUpdateEnclaveIdentity{}

func NewMsgPioneerUpdateEnclaveIdentity(creator string, uniqueID string, signerID string, productID string, status string, remoteReport []byte) *MsgPioneerUpdateEnclaveIdentity {
	return &MsgPioneerUpdateEnclaveIdentity{
		Creator:      creator,
		UniqueID:     uniqueID,
		SignerID:     signerID,
		ProductID:    productID,
		Status:       status,
		RemoteReport: remoteReport,
	}
}

func (msg *MsgPioneerUpdateEnclaveIdentity) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid creator address (%s)", err)
	}
	return nil
}
