package types_test

import (
	"testing"

	"qadena_v3/x/nameservice/types"

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
				// this line is used by starport scaffolding # types/genesis/validField
			},
			valid: true,
		},
		{
			desc: "duplicated nameBinding",
			genState: &types.GenesisState{
				NameBindingList: []types.NameBinding{
					{
						Credential:     "0",
						CredentialType: "0",
					},
					{
						Credential:     "0",
						CredentialType: "0",
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
