package keeper

import (
	"context"

	"qadena/x/dsvs/types"
	c "qadena/x/qadena/common"
	qadenatypes "qadena/x/qadena/types"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// AUTHORIZATION:
//
//	make sure that the creator *IS* the dsvs service provider
//	make sure that all the required signatory vshares ccPubK has ss interval public key
func (k msgServer) CreateDocument(goCtx context.Context, msg *types.MsgCreateDocument) (*types.MsgCreateDocumentResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	creatorIntervalPubKID, found := k.qadenaKeeper.GetIntervalPublicKeyIDByPubKID(ctx, msg.Creator)

	if !found {
		return nil, types.ErrServiceProviderUnauthorized
	}

	if creatorIntervalPubKID.GetServiceProviderType() != qadenatypes.DSVSServiceProvider {
		return nil, types.ErrServiceProviderUnauthorized
	}

	ccPubK := make([]c.VSharePubKInfo, 0)

	ccPubK, err := DSVSMsgServerAppendRequiredChainCCPubK(ctx, ccPubK, k.qadenaKeeper, "", false)

	if err != nil {
		return nil, err
	}

	c.ContextDebug(ctx, "requiredSignatory.VShareBind "+c.PrettyPrint(msg.RequiredSignatory))

	// validate that the msg.RequiredSignatory are properly encrypted
	for _, requiredSignatory := range msg.RequiredSignatory {
		// convert from dsvs.VShareBindData to qadena.VShareBindData
		if !c.DSVSValidateVShare(ctx, requiredSignatory.SignatoryVShareBind, requiredSignatory.EncSignatoryVShare, ccPubK) {
			return nil, types.ErrInvalidVShare
		}
	}

	walletID := msg.Creator

	c.ContextDebug(ctx, "CreateDocument "+walletID)

	// need to check permissions if the creator can create a document

	c.ContextDebug(ctx, "Creating Document")

	// need to check if the document already exists

	_, found = k.GetDocument(ctx, msg.DocumentID)

	if found {
		return nil, types.ErrDocumentExists
	}

	// check if the hash already exists
	_, found = k.GetDocumentHash(ctx, msg.Hash)

	if found {
		return nil, types.ErrHashExists
	}

	// create hashinfo
	hashInfo := types.HashInfo{
		Version: 1,
		Hash:    msg.Hash,
	}
	// create array of hashinfo
	hashInfoArray := []*types.HashInfo{&hashInfo}

	d := types.Document{DocumentID: msg.DocumentID,
		DocumentType:      msg.DocumentType,
		CompanyName:       msg.CompanyName,
		RequiredSignatory: msg.RequiredSignatory,
		Hash:              hashInfoArray,
	}

	c.ContextDebug(ctx, "document "+d.String())

	k.SetDocument(ctx, d)

	c.ContextDebug(ctx, "saved document")

	// store hash

	k.SetDocumentHash(ctx, types.DocumentHash{Hash: msg.Hash, DocumentID: msg.DocumentID})

	return &types.MsgCreateDocumentResponse{}, nil
}
