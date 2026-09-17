package cli

import (
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"
)

// The store is keyed by the pioneer's ACCOUNT address; operators copy the OPERATOR address out of
// `query staking validators`.  A missed conversion returns NotFound, which reads as "nothing is
// parked" -- the wrong answer to exactly the question this command exists for.
func TestParkedPubKIDFromArg(t *testing.T) {
	keyBytes := []byte("parked-cli-test-key!")
	acct := sdk.AccAddress(keyBytes).String()
	valoper := sdk.ValAddress(keyBytes).String()
	require.NotEqual(t, acct, valoper)

	got, err := parkedPubKIDFromArg(valoper)
	require.NoError(t, err)
	require.Equal(t, acct, got, "a valoper address must map to the same key's account address")

	got, err = parkedPubKIDFromArg(acct)
	require.NoError(t, err)
	require.Equal(t, acct, got, "an account address passes through unchanged")

	_, err = parkedPubKIDFromArg(valoper[:len(valoper)-1] + "x")
	require.Error(t, err, "a corrupted valoper must be refused, not passed through as a key")
}
