package types

import (
	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

var _ sdk.Msg = &MsgPioneerUpdateEnclaveIdentity{}

// height is the chain height the remote report was generated at, and is bound INTO the report's
// certified data -- see MsgPioneerUpdateEnclaveIdentity.height in tx.proto.  Restating it here
// without regenerating the report simply makes the report fail to verify.
func NewMsgPioneerUpdateEnclaveIdentity(creator string, uniqueID string, signerID string, productID string, status string, remoteReport []byte, height int64) *MsgPioneerUpdateEnclaveIdentity {
	return &MsgPioneerUpdateEnclaveIdentity{
		Creator:      creator,
		UniqueID:     uniqueID,
		SignerID:     signerID,
		ProductID:    productID,
		Status:       status,
		RemoteReport: remoteReport,
		Height:       height,
	}
}

func (msg *MsgPioneerUpdateEnclaveIdentity) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid creator address (%s)", err)
	}
	return nil
}
