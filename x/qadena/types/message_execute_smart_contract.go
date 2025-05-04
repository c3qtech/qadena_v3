package types

import (
	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

var _ sdk.Msg = &MsgExecuteSmartContract{}

func NewMsgExecuteSmartContract(creator string, srcWalletID string, smartContractHex string) *MsgExecuteSmartContract {
	return &MsgExecuteSmartContract{
		Creator:          creator,
		SrcWalletID:      srcWalletID,
		SmartContractHex: smartContractHex,
	}
}

func (msg *MsgExecuteSmartContract) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid creator address (%s)", err)
	}
	return nil
}
