package keeper

import (
	"context"

	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"
	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

func (k msgServer) UpdateParams(goCtx context.Context, req *types.MsgUpdateParams) (*types.MsgUpdateParamsResponse, error) {
	if k.GetAuthority() != req.Authority {
		return nil, errorsmod.Wrapf(types.ErrInvalidSigner, "invalid authority; expected %s, got %s", k.GetAuthority(), req.Authority)
	}

	ctx := sdk.UnwrapSDKContext(goCtx)

	// Validated HERE, because this is the path governance actually uses and it was skipping the
	// check entirely: Params.Validate() was only ever reached from genesis, and SetParams marshals
	// whatever it is handed.  A proposal carrying a value that silently disables a control -- a
	// negative update cool-down, say -- would pass its vote and take effect with nothing logged.
	//
	// Rejecting at execution means the proposal shows up as FAILED with the reason attached, rather
	// than as a passed proposal whose effect nobody notices.
	if err := req.Params.Validate(); err != nil {
		c.ContextError(ctx, "rejecting MsgUpdateParams: "+err.Error())
		return nil, errorsmod.Wrapf(types.ErrInvalidOperation, "invalid params: %s", err.Error())
	}

	if err := k.SetParams(ctx, req.Params); err != nil {
		return nil, err
	}

	return &types.MsgUpdateParamsResponse{}, nil
}
