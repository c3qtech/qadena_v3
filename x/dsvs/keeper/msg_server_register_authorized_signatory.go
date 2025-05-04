package keeper

import (
	"context"

	"qadena/x/dsvs/types"
	qadenatypes "qadena/x/qadena/types"

	c "qadena/x/qadena/common"

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

	vss := c.VShareSignatory{
		EncSignatoryVShare: msg.VShareAuthorizedSignatory.EncAuthorizedSignatoryVShare,
		VShareBind:         unprotoized,
	}

	// get authorized signatory
	signatory, found := k.GetAuthorizedSignatory(ctx, msg.Creator)

	array_vss := make([]*c.VShareSignatory, 0)
	for _, v := range signatory.Signatory {
		tvss := c.VShareSignatory{
			EncSignatoryVShare: v.EncAuthorizedSignatoryVShare,
			VShareBind:         c.DSVSUnprotoizeVShareBindData(v.AuthorizedSignatoryVShareBind),
		}
		array_vss = append(array_vss, &tvss)
	}

	success, err := k.qadenaKeeper.EnclaveValidateAuthorizedSignatory(ctx, msg.Creator, c.ProtoizeVShareSignatory(&vss), c.ProtoizeArrayOfVShareSignatory(array_vss))

	if success {
		//signatory, found = k.GetAuthorizedSignatory(ctx, msg.Creator)

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
		msg.VShareAuthorizedSignatory.Time = ctx.BlockTime()
		k.SetAuthorizedSignatory(ctx, signatory)
		return &types.MsgRegisterAuthorizedSignatoryResponse{}, nil
	} else {
		return nil, err
	}
}
