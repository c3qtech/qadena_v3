package keeper

import (
	"context"

	"github.com/c3qtech/qadena_v3/x/dsvs/types"
	qadenatypes "github.com/c3qtech/qadena_v3/x/qadena/types"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// AUTHORIZATION:
//
//	make sure that the creator *HAS* the dsvs service provider, and that the signatory vshare ccPubK has its public key
//	make sure that the signatory vshare ccPubK has ss interval public key
func (k msgServer) RegisterAuthorizedSignatory(goCtx context.Context, msg *types.MsgRegisterAuthorizedSignatory) (*types.MsgRegisterAuthorizedSignatoryResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	ccPubK := make([]c.VSharePubKInfo, 0)

	ccPubK, err := DSVSMsgServerAppendRequiredChainCCPubK(ctx, ccPubK, k.qadenaKeeper, "", false)

	if err != nil {
		return nil, err
	}

	// now get the wallet
	creatorWallet, found := k.qadenaKeeper.GetWallet(ctx, msg.Creator)

	if !found {
		return nil, types.ErrWalletNotFound
	}

	ccPubK, err = DSVSMsgServerAppendAuthorizeUser(ctx, ccPubK, k.qadenaKeeper, creatorWallet, qadenatypes.DSVSServiceProvider)

	if err != nil {
		return nil, err
	}

	if !c.DSVSValidateVShare(ctx, msg.VShareAuthorizedSignatory.AuthorizedSignatoryVShareBind, msg.VShareAuthorizedSignatory.EncAuthorizedSignatoryVShare, ccPubK) {
		return nil, types.ErrInvalidVShare
	}

	unprotoized := c.DSVSUnprotoizeVShareBindData(msg.VShareAuthorizedSignatory.AuthorizedSignatoryVShareBind)

	currentVSS := c.VShareSignatory{
		EncSignatoryVShare: msg.VShareAuthorizedSignatory.EncAuthorizedSignatoryVShare,
		VShareBind:         unprotoized,
		Time:               ctx.BlockTime(),
	}

	// get authorized signatory
	signatory, found := k.GetAuthorizedSignatory(ctx, msg.Creator)

	array_old_vss := make([]*c.VShareSignatory, 0)
	for _, v := range signatory.Signatory {
		tvss := c.VShareSignatory{
			EncSignatoryVShare: v.EncAuthorizedSignatoryVShare,
			VShareBind:         c.DSVSUnprotoizeVShareBindData(v.AuthorizedSignatoryVShareBind),
			Time:               v.Time,
		}
		array_old_vss = append(array_old_vss, &tvss)
	}

	success, err := k.qadenaKeeper.EnclaveValidateAuthorizedSignatory(ctx, msg.Creator, c.ProtoizeVShareSignatory(&currentVSS), c.ProtoizeArrayOfVShareSignatory(array_old_vss))

	if success {
		//signatory, found = k.GetAuthorizedSignatory(ctx, msg.Creator)

		msg.VShareAuthorizedSignatory.Time = ctx.BlockTime() // this sets the time that this new signatory was added
		if !found {
			//k.SetAuthorizedSignatory(ctx, signatory)
			signatory = types.AuthorizedSignatory{
				WalletID: msg.Creator,
				Signatory: []*types.VShareAuthorizedSignatory{
					msg.VShareAuthorizedSignatory,
				},
			}
		} else {
			signatory.Signatory = append(signatory.Signatory, msg.VShareAuthorizedSignatory)
		}
		k.SetAuthorizedSignatory(ctx, signatory)
		return &types.MsgRegisterAuthorizedSignatoryResponse{}, nil
	} else {
		return nil, err
	}
}
