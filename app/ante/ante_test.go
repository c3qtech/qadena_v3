package ante

import (
	"errors"
	"fmt"
	"testing"

	storetypes "cosmossdk.io/store/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/stretchr/testify/require"
)

// panicDecorator panics with whatever it was handed, standing in for the vendored
// signature-verification path.
type panicDecorator struct{ v any }

func (d panicDecorator) AnteHandle(sdk.Context, sdk.Tx, bool, sdk.AnteHandler) (sdk.Context, error) {
	panic(d.v)
}

type okDecorator struct{ called *bool }

func (d okDecorator) AnteHandle(ctx sdk.Context, _ sdk.Tx, _ bool, _ sdk.AnteHandler) (sdk.Context, error) {
	*d.called = true
	return ctx, nil
}

func run(inner sdk.AnteDecorator) (err error) {
	_, err = sigVerifyNoPanic{inner}.AnteHandle(sdk.Context{}, nil, false, nil)
	return err
}

// The amino panic becomes an ordinary unauthorized error instead of unwinding.
func TestAbsorbsAminoCodecPanic(t *testing.T) {
	inner := panicDecorator{fmt.Errorf("must set RegressionTestingAminoCodec before calling StdSignBytes")}

	var err error
	require.NotPanics(t, func() { err = run(inner) })
	require.Error(t, err)
	require.ErrorIs(t, err, sdkerrors.ErrUnauthorized)
	require.Contains(t, err.Error(), "signature verification failed")
	// The amino noise must not leak through to the broadcaster.
	require.NotContains(t, err.Error(), aminoCodecPanicMarker)
}

// Everything else must keep unwinding -- absorbing an unrelated panic would hide a
// real bug, and baseapp handles ErrorOutOfGas itself.
func TestRepanicsEverythingElse(t *testing.T) {
	cases := map[string]any{
		"unrelated error": errors.New("something else went wrong"),
		"string panic":    "raw string panic",
		"out of gas":      storetypes.ErrorOutOfGas{Descriptor: "sig verify"},
		"nil deref":       (*struct{ x int })(nil),
	}

	for name, v := range cases {
		t.Run(name, func(t *testing.T) {
			require.PanicsWithValue(t, v, func() { _ = run(panicDecorator{v}) })
		})
	}
}

// The happy path is untouched: the inner decorator runs and its result passes through.
func TestPassesThroughWhenNoPanic(t *testing.T) {
	called := false
	require.NoError(t, run(okDecorator{&called}))
	require.True(t, called, "inner decorator should have been called")
}
