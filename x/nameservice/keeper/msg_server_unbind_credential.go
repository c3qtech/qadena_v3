package keeper

import (
	"context"

	"github.com/c3qtech/qadena_v3/x/nameservice/types"

	sdk "github.com/cosmos/cosmos-sdk/types"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"
)

// AUTHORIZATION:
//
//	the creator must be the address the binding currently points at
//
// Unlike BindCredential there is no credential proof: binding a contact requires proving you hold
// it, but giving one up requires only that it currently names you.  Demanding a proof here would
// make a binding impossible to remove precisely when the user has lost the contact -- which is the
// main reason to remove one.
func (k msgServer) UnbindCredential(goCtx context.Context, msg *types.MsgUnbindCredential) (*types.MsgUnbindCredentialResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	c.ContextDebug(ctx, "UnbindCredential msg", "msg", c.PrettyPrint(msg))

	binding, found := k.GetNameBinding(ctx, msg.CredentialInfo, msg.CredentialType)
	if !found {
		c.ContextDebug(ctx, "name binding not found "+msg.CredentialInfo+" "+msg.CredentialType)
		return nil, types.ErrNameBindingNotExists
	}

	if binding.Address != msg.Creator {
		c.ContextError(ctx, "name binding "+msg.CredentialInfo+" points at "+binding.Address+", not "+msg.Creator)
		return nil, types.ErrNameBindingNotOwner
	}

	k.RemoveNameBinding(ctx, msg.CredentialInfo, msg.CredentialType)

	return &types.MsgUnbindCredentialResponse{}, nil
}
