package keeper

import (
	"context"

	"github.com/c3qtech/qadena_v3/x/qadena/types"
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
