package types

import (
	"testing"

	"github.com/c3qtech/qadena_v3/testutil/sample"

	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/stretchr/testify/require"
)

func TestMsgTransferFunds_ValidateBasic(t *testing.T) {
	tests := []struct {
		name string
		msg  MsgTransferFunds
		err  error
	}{
		{
			name: "invalid address",
			msg: MsgTransferFunds{
				Creator: "invalid_address",
			},
			err: sdkerrors.ErrInvalidAddress,
		}, {
			name: "valid address",
			msg: MsgTransferFunds{
				Creator: sample.AccAddress(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.msg.ValidateBasic()
			if tt.err != nil {
				require.ErrorIs(t, err, tt.err)
				return
			}
			require.NoError(t, err)
		})
	}
}
