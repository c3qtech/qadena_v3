package types

import (
	"time"

	errorsmod "cosmossdk.io/errors"
	"cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

var _ sdk.Msg = &MsgPostPrice{}

func NewMsgPostPrice(creator string, marketId string, price math.LegacyDec, expiry time.Time) *MsgPostPrice {
	return &MsgPostPrice{
		Creator:  creator,
		MarketId: marketId,
		Price:    price,
		Expiry:   expiry,
	}
}

func (msg *MsgPostPrice) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid creator address (%s)", err)
	}
	return nil
}
