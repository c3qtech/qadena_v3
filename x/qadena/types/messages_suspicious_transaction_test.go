package types

import (
	"testing"

	"qadena_v3/testutil/sample"

	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/stretchr/testify/require"
)

func TestMsgCreateSuspiciousTransaction_ValidateBasic(t *testing.T) {
	tests := []struct {
		name string
		msg  MsgCreateSuspiciousTransaction
		err  error
	}{
		{
			name: "invalid address",
			msg: MsgCreateSuspiciousTransaction{
				Creator: "invalid_address",
			},
			err: sdkerrors.ErrInvalidAddress,
		}, {
			name: "valid address",
			msg: MsgCreateSuspiciousTransaction{
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

func TestMsgUpdateSuspiciousTransaction_ValidateBasic(t *testing.T) {
	tests := []struct {
		name string
		msg  MsgUpdateSuspiciousTransaction
		err  error
	}{
		{
			name: "invalid address",
			msg: MsgUpdateSuspiciousTransaction{
				Creator: "invalid_address",
			},
			err: sdkerrors.ErrInvalidAddress,
		}, {
			name: "valid address",
			msg: MsgUpdateSuspiciousTransaction{
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

func TestMsgDeleteSuspiciousTransaction_ValidateBasic(t *testing.T) {
	tests := []struct {
		name string
		msg  MsgDeleteSuspiciousTransaction
		err  error
	}{
		{
			name: "invalid address",
			msg: MsgDeleteSuspiciousTransaction{
				Creator: "invalid_address",
			},
			err: sdkerrors.ErrInvalidAddress,
		}, {
			name: "valid address",
			msg: MsgDeleteSuspiciousTransaction{
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
