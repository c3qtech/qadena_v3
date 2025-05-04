package types

import (
	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

var _ sdk.Msg = &MsgReceiveFunds{}

func NewMsgReceiveFunds(creator string, transactionID string, destinationPC *BPedersenCommit, hiddenTransferPC *BPedersenCommit, newDestinationPC *BPedersenCommit, encNewDestinationWalletAmount []byte,
	newDestinationWalletAmountVShareBind *VShareBindData, encAnonReceiveFundsVShare []byte, anonReceiveFundsVShareBind *VShareBindData, transparentAmount *BInt, tokenDenom string, hiddenTransferPCProof *BRangeProof,
	newDestinationPCProof *BRangeProof, encReceiveFundsVShare []byte, receiveFundsVShareBind *VShareBindData) *MsgReceiveFunds {
	return &MsgReceiveFunds{
		Creator:                              creator,
		TransactionID:                        transactionID,
		DestinationPC:                        destinationPC,
		HiddenTransferPC:                     hiddenTransferPC,
		NewDestinationPC:                     newDestinationPC,
		EncNewDestinationWalletAmountVShare:  encNewDestinationWalletAmount,
		NewDestinationWalletAmountVShareBind: newDestinationWalletAmountVShareBind,
		EncAnonReceiveFundsVShare:            encAnonReceiveFundsVShare,
		AnonReceiveFundsVShareBind:           anonReceiveFundsVShareBind,
		TransparentAmount:                    transparentAmount,
		TokenDenom:                           tokenDenom,
		HiddenTransferPCProof:                hiddenTransferPCProof,
		NewDestinationPCProof:                newDestinationPCProof,
		EncReceiveFundsVShare:                encReceiveFundsVShare,
		ReceiveFundsVShareBind:               receiveFundsVShareBind,
	}
}

func (msg *MsgReceiveFunds) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid creator address (%s)", err)
	}
	return nil
}
