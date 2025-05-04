package keeper

import (
	"context"

	"qadena/x/nameservice/types"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"fmt"

	c "qadena/x/qadena/common"
	qadenatypes "qadena/x/qadena/types"
)

func (k msgServer) BindCredential(goCtx context.Context, msg *types.MsgBindCredential) (*types.MsgBindCredentialResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	fmt.Println(msg, c.PrettyPrint(msg))

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
