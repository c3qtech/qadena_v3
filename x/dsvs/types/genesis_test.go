package types_test

import (
	"testing"

	"qadena_v3/x/dsvs/types"

	"github.com/stretchr/testify/require"
)

func TestGenesisState_Validate(t *testing.T) {
	tests := []struct {
		desc     string
		genState *types.GenesisState
		valid    bool
	}{
		{
			desc:     "default is valid",
			genState: types.DefaultGenesis(),
			valid:    true,
		},
		{
			desc: "valid genesis state",
			genState: &types.GenesisState{

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
				// this line is used by starport scaffolding # types/genesis/validField
			},
			valid: true,
		},
		{
			desc: "duplicated documentHash",
			genState: &types.GenesisState{
				DocumentHashList: []types.DocumentHash{
					{
						Hash: []byte("0"),
					},
					{
						Hash: []byte("0"),
					},
				},
			},
			valid: false,
		},
		{
			desc: "duplicated document",
			genState: &types.GenesisState{
				DocumentList: []types.Document{
					{
						DocumentID: "0",
					},
					{
						DocumentID: "0",
					},
				},
			},
			valid: false,
		},
		{
			desc: "duplicated authorizedSignatory",
			genState: &types.GenesisState{
				AuthorizedSignatoryList: []types.AuthorizedSignatory{
					{
						WalletID: "0",
					},
					{
						WalletID: "0",
					},
				},
			},
			valid: false,
		},
		// this line is used by starport scaffolding # types/genesis/testcase
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			err := tc.genState.Validate()
			if tc.valid {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}
