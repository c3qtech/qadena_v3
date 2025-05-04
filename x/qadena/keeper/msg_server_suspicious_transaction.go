package keeper

import (
	"context"

	"qadena/x/qadena/types"
)

func (k msgServer) CreateSuspiciousTransaction(goCtx context.Context, msg *types.MsgCreateSuspiciousTransaction) (*types.MsgCreateSuspiciousTransactionResponse, error) {
	return nil, types.ErrInvalidOperation
}

func (k msgServer) UpdateSuspiciousTransaction(goCtx context.Context, msg *types.MsgUpdateSuspiciousTransaction) (*types.MsgUpdateSuspiciousTransactionResponse, error) {
	return nil, types.ErrInvalidOperation
}

func (k msgServer) DeleteSuspiciousTransaction(goCtx context.Context, msg *types.MsgDeleteSuspiciousTransaction) (*types.MsgDeleteSuspiciousTransactionResponse, error) {
	return nil, types.ErrInvalidOperation
}
