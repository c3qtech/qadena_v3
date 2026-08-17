package keeper

import (
	"context"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/c3qtech/qadena_v3/x/qadena/common"

	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

func (k msgServer) PioneerUpdateEnclaveIdentity(goCtx context.Context, msg *types.MsgPioneerUpdateEnclaveIdentity) (*types.MsgPioneerUpdateEnclaveIdentityResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	common.ContextDebug(ctx, "PioneerUpdateEnclaveIdentity")

	enclaveIdentity := types.EnclaveIdentity{
		UniqueID: msg.UniqueID,
		SignerID: msg.SignerID,
		Status:   msg.Status,
	}

	updateEnclaveIdentity := types.PioneerUpdateEnclaveIdentity{
		EnclaveIdentity: &enclaveIdentity,
		RemoteReport:    msg.RemoteReport,
		Height:          msg.Height,
	}

	// BEST EFFORT, and deliberately not fatal.
	//
	// This used to `return nil, err` when the enclave refused the report, which made a CONSENSUS
	// OUTCOME depend on whether an SGX quote still verified.  DCAP verification consumes collateral
	// with validity windows and TCB levels that are revised when vulnerabilities are found, so two
	// nodes checking the same historical report on different days can legitimately disagree -- and a
	// node replaying this transaction from history would take a different path than the network did
	// when it was live, write different state, and halt on a mismatched app hash.
	//
	// Whether THIS enclave trusts the measurement is a local judgement that may differ between nodes
	// and over time; the row below is consensus state that must replay identically on every node
	// forever.  Now that trust lives outside the mirrored store, letting them differ costs nothing.
	// The message is still pioneer-signed, so this is not an open door: an unattested submission
	// records a row that confers trust on nobody.
	if err := k.Keeper.EnclaveClientUpdateEnclaveIdentity(ctx, updateEnclaveIdentity); err != nil {
		common.ContextError(ctx, "enclave did not accept the attested identity "+msg.UniqueID+" ("+msg.Status+"): "+err.Error()+
			" -- recording the row anyway; this node simply does not trust that measurement")
	}

	k.Keeper.SetEnclaveIdentityNoEnclave(ctx, enclaveIdentity)

	return &types.MsgPioneerUpdateEnclaveIdentityResponse{}, nil
}
