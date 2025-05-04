package types

import (
	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

var _ sdk.Msg = &MsgTransferFunds{}

func NewMsgTransferFunds(creator string, transactionID string, sourcePC *BPedersenCommit, hiddenTransferPC *BPedersenCommit,
	newSourcePC *BPedersenCommit, encNewSourceWalletAmountVShare []byte, newSourceWalletAmountVShareBind *VShareBindData, encNewDestinationWalletAmountVShare []byte, newDestinationWalletAmountVShareBind *VShareBindData,
	encAnonTransferFunds []byte, anonTransferFundsVShareBind *VShareBindData,
	transparentAmount *BInt, tokenDenom string, hiddenTransferPCProof *BRangeProof, newSourcePCProof *BRangeProof,
	encTransferFundsVShare []byte, transferFundsVShareBind *VShareBindData) *MsgTransferFunds {
	return &MsgTransferFunds{
		Creator:                              creator,
		TransactionID:                        transactionID,
		SourcePC:                             sourcePC,
		HiddenTransferPC:                     hiddenTransferPC,
		NewSourcePC:                          newSourcePC,
		EncNewSourceWalletAmountVShare:       encNewSourceWalletAmountVShare,
		NewSourceWalletAmountVShareBind:      newSourceWalletAmountVShareBind,
		EncNewDestinationWalletAmountVShare:  encNewDestinationWalletAmountVShare,
		NewDestinationWalletAmountVShareBind: newDestinationWalletAmountVShareBind,
		EncAnonTransferFundsVShare:           encAnonTransferFunds,
		AnonTransferFundsVShareBind:          anonTransferFundsVShareBind,
		TransparentAmount:                    transparentAmount,
		TokenDenom:                           tokenDenom,
		HiddenTransferPCProof:                hiddenTransferPCProof,
		NewSourcePCProof:                     newSourcePCProof,
		EncTransferFundsVShare:               encTransferFundsVShare,
		TransferFundsVShareBind:              transferFundsVShareBind,
	}
}

func (msg *MsgTransferFunds) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid creator address (%s)", err)
	}
	return nil
}
