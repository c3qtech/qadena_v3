package types

import (
	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

var _ sdk.Msg = &MsgCreateDocument{}

func NewMsgCreateDocumentWithMetadata(creator string, documentType string, companyName string, requiredSignatory []*VShareSignatory, hash []byte, metadata string) *MsgCreateDocument {
	return &MsgCreateDocument{
		Creator:           creator,
		DocumentType:      documentType,
		CompanyName:       companyName,
		RequiredSignatory: requiredSignatory,
		Hash:              hash,
		Metadata:          metadata,
	}
}

// optional metadata field
func NewMsgCreateDocument(creator string, documentType string, companyName string, requiredSignatory []*VShareSignatory, hash []byte) *MsgCreateDocument {
	return &MsgCreateDocument{
		Creator:           creator,
		DocumentType:      documentType,
		CompanyName:       companyName,
		RequiredSignatory: requiredSignatory,
		Hash:              hash,
		Metadata:          "",
	}
}

func (msg *MsgCreateDocument) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid creator address (%s)", err)
	}
	return nil
}
