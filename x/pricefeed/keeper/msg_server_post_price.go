package keeper

import (
	"context"

	"qadena/x/pricefeed/types"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

func (k msgServer) PostPrice(goCtx context.Context, msg *types.MsgPostPrice) (*types.MsgPostPriceResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	from, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return nil, err
	}

	_, err = k.GetOracle(ctx, msg.MarketId, from)
	if err != nil {
		return nil, err
	}

	_, err = k.SetPrice(ctx, from, msg.MarketId, msg.Price, msg.Expiry)
	if err != nil {
		return nil, err
	}

	ctx.EventManager().EmitEvent(
		sdk.NewEvent(
			sdk.EventTypeMessage,
			sdk.NewAttribute(sdk.AttributeKeyModule, types.AttributeValueCategory),
			sdk.NewAttribute(sdk.AttributeKeySender, msg.Creator),
		),
	)

	return &types.MsgPostPriceResponse{}, nil
}
