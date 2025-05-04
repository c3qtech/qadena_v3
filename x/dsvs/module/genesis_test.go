package dsvs_test

import (
	"testing"

	keepertest "github.com/c3qtech/qadena_v3/testutil/keeper"
	"github.com/c3qtech/qadena_v3/testutil/nullify"
	dsvs "github.com/c3qtech/qadena_v3/x/dsvs/module"
	"github.com/c3qtech/qadena_v3/x/dsvs/types"

	"github.com/stretchr/testify/require"
)

func TestGenesis(t *testing.T) {
	genesisState := types.GenesisState{
		Params: types.DefaultParams(),

		DocumentHashList: []types.DocumentHash{
			{
				Hash: []byte("0"),
			},
			{
				Hash: []byte("1"),
			},
		},
		DocumentList: []types.Document{
			{
				DocumentID: "0",
			},
			{
				DocumentID: "1",
			},
		},
		AuthorizedSignatoryList: []types.AuthorizedSignatory{
			{
				WalletID: "0",
			},
			{
				WalletID: "1",
			},
		},
		// this line is used by starport scaffolding # genesis/test/state
	}

	k, ctx := keepertest.DsvsKeeper(t)
	dsvs.InitGenesis(ctx, k, genesisState)
	got := dsvs.ExportGenesis(ctx, k)
	require.NotNil(t, got)

	nullify.Fill(&genesisState)
	nullify.Fill(got)

	require.ElementsMatch(t, genesisState.DocumentHashList, got.DocumentHashList)
	require.ElementsMatch(t, genesisState.DocumentList, got.DocumentList)
	require.ElementsMatch(t, genesisState.AuthorizedSignatoryList, got.AuthorizedSignatoryList)
	// this line is used by starport scaffolding # genesis/test/assert
}
