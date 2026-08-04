package keeper

import (
	"context"

	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/c3qtech/qadena_v3/x/qadena/common"
	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

// Governance control of the bank-send whitelist.
//
// One address per message, deliberately.  The alternative -- carrying the list in Params -- would
// mean MsgUpdateParams replacing it wholesale, so adding one deployment's treasury would require
// restating every other deployment's, and an omission would silently revoke an exemption instead of
// failing.  Each deployment adds and removes only its own entry.

func (k msgServer) AddBankSendWhitelist(goCtx context.Context, msg *types.MsgAddBankSendWhitelist) (*types.MsgAddBankSendWhitelistResponse, error) {
	if k.GetAuthority() != msg.Authority {
		return nil, errorsmod.Wrapf(types.ErrInvalidSigner, "invalid authority; expected %s, got %s", k.GetAuthority(), msg.Authority)
	}

	ctx := sdk.UnwrapSDKContext(goCtx)

	if _, err := sdk.AccAddressFromBech32(msg.Address); err != nil {
		return nil, errorsmod.Wrapf(types.ErrInvalidCreator, "whitelist address %q is not a valid address", msg.Address)
	}

	// Refuse a duplicate rather than overwriting.  A proposal that turns out to be a no-op should
	// fail visibly: silently re-adding would also silently replace the recorded reason, losing the
	// justification the original entry was approved under.
	if _, found := k.GetBankSendWhitelist(ctx, msg.Address); found {
		return nil, errorsmod.Wrapf(types.ErrBankSendWhitelistExists, "%s", msg.Address)
	}

	common.ContextDebug(ctx, "AddBankSendWhitelist "+msg.Address+" ("+msg.Reason+")")

	k.Keeper.SetBankSendWhitelist(ctx, types.BankSendWhitelist{
		Address: msg.Address,
		Reason:  msg.Reason,
	})

	return &types.MsgAddBankSendWhitelistResponse{}, nil
}

func (k msgServer) RemoveBankSendWhitelist(goCtx context.Context, msg *types.MsgRemoveBankSendWhitelist) (*types.MsgRemoveBankSendWhitelistResponse, error) {
	if k.GetAuthority() != msg.Authority {
		return nil, errorsmod.Wrapf(types.ErrInvalidSigner, "invalid authority; expected %s, got %s", k.GetAuthority(), msg.Authority)
	}

	ctx := sdk.UnwrapSDKContext(goCtx)

	// Refuse to remove what is not there, for the same reason: a proposal that passes having done
	// nothing reads as though an exemption was revoked when it never existed.
	if _, found := k.GetBankSendWhitelist(ctx, msg.Address); !found {
		return nil, errorsmod.Wrapf(types.ErrBankSendWhitelistNotFound, "%s", msg.Address)
	}

	common.ContextDebug(ctx, "RemoveBankSendWhitelist "+msg.Address)

	k.Keeper.RemoveBankSendWhitelist(ctx, msg.Address)

	return &types.MsgRemoveBankSendWhitelistResponse{}, nil
}
