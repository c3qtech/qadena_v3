package types

import (
	time "time"

	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

var _ sdk.Msg = &MsgCreateSuspiciousTransaction{}

func NewMsgCreateSuspiciousTransaction(creator string, jarID string, regulatorPubKID string, reason string, time time.Time, encSourcePersonalInfoRegulatorPubK []byte, encDestinationPersonalInfoRegulatorPubK []byte, encEAmountRegulatorPubK []byte, encOptInReasonRegulatorPubK []byte) *MsgCreateSuspiciousTransaction {
	return &MsgCreateSuspiciousTransaction{
		Creator:                                 creator,
		JarID:                                   jarID,
		RegulatorPubKID:                         regulatorPubKID,
		Reason:                                  reason,
		Time:                                    time,
		EncSourcePersonalInfoRegulatorPubK:      encSourcePersonalInfoRegulatorPubK,
		EncDestinationPersonalInfoRegulatorPubK: encDestinationPersonalInfoRegulatorPubK,
		EncEAmountRegulatorPubK:                 encEAmountRegulatorPubK,
		EncOptInReasonRegulatorPubK:             encOptInReasonRegulatorPubK,
	}
}

func (msg *MsgCreateSuspiciousTransaction) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid creator address (%s)", err)
	}
	return nil
}

var _ sdk.Msg = &MsgUpdateSuspiciousTransaction{}

func NewMsgUpdateSuspiciousTransaction(creator string, id uint64, jarID string, regulatorPubKID string, reason string, time time.Time, encSourcePersonalInfoRegulatorPubK []byte, encDestinationPersonalInfoRegulatorPubK []byte, encEAmountRegulatorPubK []byte, encOptInReasonRegulatorPubK []byte) *MsgUpdateSuspiciousTransaction {
	return &MsgUpdateSuspiciousTransaction{
		Id:                                      id,
		Creator:                                 creator,
		JarID:                                   jarID,
		RegulatorPubKID:                         regulatorPubKID,
		Reason:                                  reason,
		Time:                                    time,
		EncSourcePersonalInfoRegulatorPubK:      encSourcePersonalInfoRegulatorPubK,
		EncDestinationPersonalInfoRegulatorPubK: encDestinationPersonalInfoRegulatorPubK,
		EncEAmountRegulatorPubK:                 encEAmountRegulatorPubK,
		EncOptInReasonRegulatorPubK:             encOptInReasonRegulatorPubK,
	}
}

func (msg *MsgUpdateSuspiciousTransaction) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid creator address (%s)", err)
	}
	return nil
}

var _ sdk.Msg = &MsgDeleteSuspiciousTransaction{}

func NewMsgDeleteSuspiciousTransaction(creator string, id uint64) *MsgDeleteSuspiciousTransaction {
	return &MsgDeleteSuspiciousTransaction{
		Id:      id,
		Creator: creator,
	}
}

func (msg *MsgDeleteSuspiciousTransaction) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid creator address (%s)", err)
	}
	return nil
}
