package keeper

import (
	"bytes"
	"context"
	"time"

	"qadena_v3/x/dsvs/types"
	c "qadena_v3/x/qadena/common"
	qadenatypes "qadena_v3/x/qadena/types"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// AUTHORIZATION:
//	make sure that the creator *HAS* the dsvs service provider, and that the signatory vshare ccPubK has its public key
//	make sure that the signatory vshare ccPubK has ss interval public key

func (k msgServer) SignDocument(goCtx context.Context, msg *types.MsgSignDocument) (*types.MsgSignDocumentResponse, error) {
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

	if !c.DSVSValidateVShare(ctx, msg.CompletedSignatory.SignatoryVShareBind, msg.CompletedSignatory.EncSignatoryVShare, ccPubK) {
		return nil, types.ErrInvalidVShare
	}

	if bytes.Equal(msg.CurrentHash, msg.Hash) {
		return nil, types.ErrHashDuplicate
	}

	// find the document by hash
	documentHash, found := k.GetDocumentHash(ctx, msg.CurrentHash)

	if !found {
		c.ContextError(ctx, "document not found by hash", msg.CurrentHash)
		return nil, types.ErrDocumentNotFound
	}

	// get the document
	document, found := k.GetDocument(ctx, documentHash.DocumentID)

	if !found {
		c.ContextError(ctx, "document not found by documentID", documentHash.DocumentID)
		return nil, types.ErrDocumentNotFound
	}

	// find the document by new hash to make sure it doesn't already exist
	_, found = k.GetDocumentHash(ctx, msg.Hash)

	if found {
		return nil, types.ErrHashExists
	}

	// check if this is the current hash, which is should be the last one in the document.Hash

	if len(document.Hash) == 0 {
		return nil, types.ErrInvalidDocument
	}

	if !bytes.Equal(document.Hash[len(document.Hash)-1].Hash, msg.CurrentHash) {
		return nil, types.ErrNotCurrentHash
	}

	// we need to check if this user is allowed to sign
	unprotoCompletedSignatory := c.DSVSUnprotoizeVShareSignatory(msg.CompletedSignatory)

	// get array of required signatories
	qadenaRequiredSignatories := make([]*qadenatypes.VShareSignatory, len(document.RequiredSignatory))

	qadenaCompletedSignatories := make([]*qadenatypes.VShareSignatory, len(document.CompletedSignatory))

	for i, v := range document.RequiredSignatory {
		tmp := c.DSVSUnprotoizeVShareSignatory(v)
		qadenaRequiredSignatories[i] = c.ProtoizeVShareSignatory(tmp)
	}

	for i, v := range document.CompletedSignatory {
		qadenaCompletedSignatories[i] = c.ProtoizeVShareSignatory(c.DSVSUnprotoizeVShareSignatory(v))
	}

	success, err := k.qadenaKeeper.EnclaveValidateAuthorizedSigner(ctx, msg.Creator, c.ProtoizeVShareSignatory(unprotoCompletedSignatory), qadenaRequiredSignatories, qadenaCompletedSignatories)

	if !success {
		return nil, err
	}

	completedSignatory := msg.CompletedSignatory
	completedSignatory.Time = time.Unix(ctx.BlockTime().Unix(), 0)
	completedSignatory.WalletID = msg.Creator

	document.CompletedSignatory = append(document.CompletedSignatory, completedSignatory)

	// get last hash version
	lastHashVersion := document.Hash[len(document.Hash)-1].Version

	// add the new hash
	document.Hash = append(document.Hash, &types.HashInfo{
		Hash:    msg.Hash,
		Version: lastHashVersion + 1,
	})

	k.SetDocument(ctx, document)

	k.SetDocumentHash(ctx, types.DocumentHash{
		Hash:       msg.Hash,
		DocumentID: document.DocumentID,
	})

	return &types.MsgSignDocumentResponse{}, nil
}
