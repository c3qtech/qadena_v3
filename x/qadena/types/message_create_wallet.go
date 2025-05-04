package types

import (
	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

var _ sdk.Msg = &MsgCreateWallet{}

func NewMsgCreateWallet(creator string, homePioneerID string, serviceProviderID []string, encCreateWalletVShare []byte, createWalletVShareBind *VShareBindData,
	acceptPasswordPC *BPedersenCommit, encAcceptValidatedCredentialsVShare []byte, acceptValidatedCredentialsVShareBind *VShareBindData,
	walletAmountPedersenCommit *EncryptablePedersenCommit, encWalletAmountVShare []byte, walletAmountVShareBind *VShareBindData,
	transparentWalletAmountPC *EncryptablePedersenCommit, acceptCredentialType string) *MsgCreateWallet {
	return &MsgCreateWallet{
		Creator:                              creator,
		HomePioneerID:                        homePioneerID,
		ServiceProviderID:                    serviceProviderID,
		EncCreateWalletVShare:                encCreateWalletVShare,
		CreateWalletVShareBind:               createWalletVShareBind,
		AcceptPasswordPC:                     acceptPasswordPC,
		EncAcceptValidatedCredentialsVShare:  encAcceptValidatedCredentialsVShare,
		AcceptValidatedCredentialsVShareBind: acceptValidatedCredentialsVShareBind,
		WalletAmountPedersenCommit:           walletAmountPedersenCommit,
		EncWalletAmountVShare:                encWalletAmountVShare,
		WalletAmountVShareBind:               walletAmountVShareBind,
		TransparentWalletAmountPC:            transparentWalletAmountPC,
		AcceptCredentialType:                 acceptCredentialType,
	}
}

func (msg *MsgCreateWallet) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid creator address (%s)", err)
	}
	return nil
}
