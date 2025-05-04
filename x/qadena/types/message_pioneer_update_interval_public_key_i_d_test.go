package types

import (
	"testing"

	"qadena_v3/testutil/sample"

	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/stretchr/testify/require"
)

func TestMsgPioneerUpdateIntervalPublicKeyID_ValidateBasic(t *testing.T) {
	tests := []struct {
		name string
		msg  MsgPioneerUpdateIntervalPublicKeyID
		err  error
	}{
		{
			name: "invalid address",
			msg: MsgPioneerUpdateIntervalPublicKeyID{
				Creator: "invalid_address",
			},
			err: sdkerrors.ErrInvalidAddress,
		}, {
			name: "valid address",
			msg: MsgPioneerUpdateIntervalPublicKeyID{
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
