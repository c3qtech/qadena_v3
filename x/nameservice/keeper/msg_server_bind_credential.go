package keeper

import (
	"context"

	"github.com/c3qtech/qadena_v3/x/nameservice/types"

	sdk "github.com/cosmos/cosmos-sdk/types"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"
	qadenatypes "github.com/c3qtech/qadena_v3/x/qadena/types"
)

func (k msgServer) BindCredential(goCtx context.Context, msg *types.MsgBindCredential) (*types.MsgBindCredentialResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	c.ContextDebug(ctx, "BindCredential msg", "msg", c.PrettyPrint(msg))

	credentialPC := c.ConvertNSToQBPedersenCommit(msg.CredentialPedersenCommit)

	valid, err := k.qadenaKeeper.ValidateCredential(ctx, &qadenatypes.MsgBindCredential{msg.Creator,
		msg.CredentialType,
		msg.CredentialInfo,
		&credentialPC,
	})

	if err != nil {
		return nil, err
	}

	if valid {
		var binding types.NameBinding
		binding.Credential = msg.CredentialInfo
		binding.CredentialType = msg.CredentialType
		binding.Address = msg.Creator
		k.SetNameBinding(ctx, binding)
	} else {
		return nil, qadenatypes.ErrInvalidCredential
	}

	return &types.MsgBindCredentialResponse{}, nil

}
