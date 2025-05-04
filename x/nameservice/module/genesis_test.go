package nameservice_test

import (
	"testing"

	keepertest "qadena_v3/testutil/keeper"
	"qadena_v3/testutil/nullify"
	nameservice "qadena_v3/x/nameservice/module"
	"qadena_v3/x/nameservice/types"

	"github.com/stretchr/testify/require"
)

func TestGenesis(t *testing.T) {
	genesisState := types.GenesisState{
		Params: types.DefaultParams(),

		NameBindingList: []types.NameBinding{
			{
				Credential:     "0",
				CredentialType: "0",
			},
			{
				Credential:     "1",
				CredentialType: "1",
			},
		},
		// this line is used by starport scaffolding # genesis/test/state
	}

	k, ctx := keepertest.NameserviceKeeper(t)
	nameservice.InitGenesis(ctx, k, genesisState)
	got := nameservice.ExportGenesis(ctx, k)
	require.NotNil(t, got)

	nullify.Fill(&genesisState)
	nullify.Fill(got)

	require.ElementsMatch(t, genesisState.NameBindingList, got.NameBindingList)
	// this line is used by starport scaffolding # genesis/test/assert
}
