package keeper

import (
	"context"
	"strconv"

	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/c3qtech/qadena_v3/x/qadena/common"
	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

// Governance control of the scanned-contract whitelist.
//
// One address per message, deliberately.  The alternative -- carrying the list in Params -- would
// mean MsgUpdateParams replacing it wholesale, so adding one deployment's treasury would require
// restating every other deployment's, and an omission would silently drop an entry instead of
// failing.  Each deployment adds and removes only its own.
//
// Being on this list does NOT switch off AML scanning.  It permits an address that holds no
// credential to take part in a bank send at all, and makes reports that name it carry a contract
// descriptor rather than a person.  The send is scanned either way.

func (k msgServer) AddScannedContractWhitelist(goCtx context.Context, msg *types.MsgAddScannedContractWhitelist) (*types.MsgAddScannedContractWhitelistResponse, error) {
	if k.GetAuthority() != msg.Authority {
		return nil, errorsmod.Wrapf(types.ErrInvalidSigner, "invalid authority; expected %s, got %s", k.GetAuthority(), msg.Authority)
	}

	ctx := sdk.UnwrapSDKContext(goCtx)

	addr, err := sdk.AccAddressFromBech32(msg.Address)
	if err != nil {
		return nil, errorsmod.Wrapf(types.ErrInvalidCreator, "whitelist address %q is not a valid address", msg.Address)
	}

	// Refuse a duplicate rather than overwriting.  A proposal that turns out to be a no-op should
	// fail visibly: silently re-adding would also silently replace the recorded reason and the
	// pinned code ID, losing the justification the original entry was approved under -- and a
	// re-add is exactly how a migrated contract would try to re-pin itself.
	if _, found := k.GetScannedContractWhitelist(ctx, msg.Address); found {
		return nil, errorsmod.Wrapf(types.ErrScannedContractExists, "%s", msg.Address)
	}

	// The entry must describe the address it names.  Both directions are mistakes worth catching
	// here, while a reviewer is still looking, rather than as a refused send weeks later:
	//
	//   contract listed with codeID 0  -- unpinned, so a later migration would inherit the approval
	//   non-contract listed with a codeID -- pins against something that will never be checked
	liveCodeID, isContract := k.contractCodeID(ctx, addr)
	if isContract != (msg.CodeID != 0) || (isContract && liveCodeID != msg.CodeID) {
		return nil, errorsmod.Wrapf(types.ErrScannedContractCodeIDMismatch,
			"%s: proposal says codeID %d, chain says %s",
			msg.Address, msg.CodeID, describeCode(liveCodeID, isContract))
	}

	common.ContextDebug(ctx, "AddScannedContractWhitelist "+msg.Address+
		" codeID "+strconv.FormatUint(msg.CodeID, 10)+" ("+msg.Reason+")")

	k.Keeper.SetScannedContractWhitelist(ctx, types.ScannedContractWhitelist{
		Address: msg.Address,
		CodeID:  msg.CodeID,
		Reason:  msg.Reason,
	})

	return &types.MsgAddScannedContractWhitelistResponse{}, nil
}

func (k msgServer) RemoveScannedContractWhitelist(goCtx context.Context, msg *types.MsgRemoveScannedContractWhitelist) (*types.MsgRemoveScannedContractWhitelistResponse, error) {
	if k.GetAuthority() != msg.Authority {
		return nil, errorsmod.Wrapf(types.ErrInvalidSigner, "invalid authority; expected %s, got %s", k.GetAuthority(), msg.Authority)
	}

	ctx := sdk.UnwrapSDKContext(goCtx)

	// Refuse to remove what is not there, for the same reason: a proposal that passes having done
	// nothing reads as though an entry was revoked when it never existed.
	if _, found := k.GetScannedContractWhitelist(ctx, msg.Address); !found {
		return nil, errorsmod.Wrapf(types.ErrScannedContractNotFound, "%s", msg.Address)
	}

	common.ContextDebug(ctx, "RemoveScannedContractWhitelist "+msg.Address)

	k.Keeper.RemoveScannedContractWhitelist(ctx, msg.Address)

	return &types.MsgRemoveScannedContractWhitelistResponse{}, nil
}

// describeCode renders what the chain actually found, for an error a proposal reviewer has to act
// on.  "not a contract" and "codeID 7" call for different corrections, and "expected 0, got 0"
// would tell them nothing.
func describeCode(codeID uint64, isContract bool) string {
	if !isContract {
		return "not a wasm contract (use codeID 0)"
	}
	return "codeID " + strconv.FormatUint(codeID, 10)
}
