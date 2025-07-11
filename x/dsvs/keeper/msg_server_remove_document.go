package keeper

import (
	"context"

	"github.com/c3qtech/qadena_v3/x/dsvs/types"
	c "github.com/c3qtech/qadena_v3/x/qadena/common"
	qadenatypes "github.com/c3qtech/qadena_v3/x/qadena/types"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// AUTHORIZATION:
//
//	make sure that the creator *IS* the dsvs service provider
//	make sure that all the required signatory vshares ccPubK has ss interval public key

// make sure that the document is not fully signed
func (k msgServer) RemoveDocument(goCtx context.Context, msg *types.MsgRemoveDocument) (*types.MsgRemoveDocumentResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	// check if the creator is a dsvs service provider
	err := k.qadenaKeeper.AuthenticateServiceProvider(ctx, msg.Creator, qadenatypes.DSVSServiceProvider)
	if err != nil {
		return nil, err
	}

	ccPubK := make([]c.VSharePubKInfo, 0)

	ccPubK, err = DSVSMsgServerAppendRequiredChainCCPubK(ctx, ccPubK, k.qadenaKeeper, "", false)

	if err != nil {
		return nil, err
	}

	walletID := msg.Creator

	c.ContextDebug(ctx, "RemoveDocument", msg.DocumentID, "by", walletID)

	// need to check if the document already exists

	document, found := k.GetDocument(ctx, msg.DocumentID)

	if !found {
		return nil, types.ErrDocumentNotFound
	}

	// check if fully signed

	if len(document.CompletedSignatory) == len(document.RequiredSignatory) {
		return nil, types.ErrDocumentFullySigned
	}

	// remove the document
	k.Keeper.RemoveDocument(ctx, msg.DocumentID)

	// remove the hashes
	for _, hash := range document.Hash {
		k.Keeper.RemoveDocumentHash(ctx, hash.Hash)
	}

	return &types.MsgRemoveDocumentResponse{}, nil
}
