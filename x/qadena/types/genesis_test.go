package types_test

import (
	"testing"

	"qadena/x/qadena/types"

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

				CredentialList: []types.Credential{
					{
						CredentialID:   "0",
						CredentialType: "0",
					},
					{
						CredentialID:   "1",
						CredentialType: "1",
					},
				},
				PublicKeyList: []types.PublicKey{
					{
						PubKID:   "0",
						PubKType: "0",
					},
					{
						PubKID:   "1",
						PubKType: "1",
					},
				},
				WalletList: []types.Wallet{
					{
						WalletID: "0",
					},
					{
						WalletID: "1",
					},
				},
				IntervalPublicKeyIDList: []types.IntervalPublicKeyID{
					{
						NodeID:   "0",
						NodeType: "0",
					},
					{
						NodeID:   "1",
						NodeType: "1",
					},
				},
				PioneerJarList: []types.PioneerJar{
					{
						PioneerID: "0",
					},
					{
						PioneerID: "1",
					},
				},
				JarRegulatorList: []types.JarRegulator{
					{
						JarID: "0",
					},
					{
						JarID: "1",
					},
				},
				SuspiciousTransactionList: []types.SuspiciousTransaction{
					{
						Id: 0,
					},
					{
						Id: 1,
					},
				},
				SuspiciousTransactionCount: 2,
				ProtectKeyList: []types.ProtectKey{
					{
						WalletID: "0",
					},
					{
						WalletID: "1",
					},
				},
				RecoverKeyList: []types.RecoverKey{
					{
						WalletID: "0",
					},
					{
						WalletID: "1",
					},
				},
				EnclaveIdentityList: []types.EnclaveIdentity{
					{
						UniqueID: "0",
					},
					{
						UniqueID: "1",
					},
				},
				// this line is used by starport scaffolding # types/genesis/validField
			},
			valid: true,
		},
		{
			desc: "duplicated credential",
			genState: &types.GenesisState{
				CredentialList: []types.Credential{
					{
						CredentialID:   "0",
						CredentialType: "0",
					},
					{
						CredentialID:   "0",
						CredentialType: "0",
					},
				},
			},
			valid: false,
		},
		{
			desc: "duplicated publicKey",
			genState: &types.GenesisState{
				PublicKeyList: []types.PublicKey{
					{
						PubKID:   "0",
						PubKType: "0",
					},
					{
						PubKID:   "0",
						PubKType: "0",
					},
				},
			},
			valid: false,
		},
		{
			desc: "duplicated wallet",
			genState: &types.GenesisState{
				WalletList: []types.Wallet{
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
		{
			desc: "duplicated intervalPublicKeyID",
			genState: &types.GenesisState{
				IntervalPublicKeyIDList: []types.IntervalPublicKeyID{
					{
						NodeID:   "0",
						NodeType: "0",
					},
					{
						NodeID:   "0",
						NodeType: "0",
					},
				},
			},
			valid: false,
		},
		{
			desc: "duplicated pioneerJar",
			genState: &types.GenesisState{
				PioneerJarList: []types.PioneerJar{
					{
						PioneerID: "0",
					},
					{
						PioneerID: "0",
					},
				},
			},
			valid: false,
		},
		{
			desc: "duplicated jarRegulator",
			genState: &types.GenesisState{
				JarRegulatorList: []types.JarRegulator{
					{
						JarID: "0",
					},
					{
						JarID: "0",
					},
				},
			},
			valid: false,
		},
		{
			desc: "duplicated suspiciousTransaction",
			genState: &types.GenesisState{
				SuspiciousTransactionList: []types.SuspiciousTransaction{
					{
						Id: 0,
					},
					{
						Id: 0,
					},
				},
			},
			valid: false,
		},
		{
			desc: "invalid suspiciousTransaction count",
			genState: &types.GenesisState{
				SuspiciousTransactionList: []types.SuspiciousTransaction{
					{
						Id: 1,
					},
				},
				SuspiciousTransactionCount: 0,
			},
			valid: false,
		},
		{
			desc: "duplicated protectKey",
			genState: &types.GenesisState{
				ProtectKeyList: []types.ProtectKey{
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
		{
			desc: "duplicated recoverKey",
			genState: &types.GenesisState{
				RecoverKeyList: []types.RecoverKey{
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
		{
			desc: "duplicated enclaveIdentity",
			genState: &types.GenesisState{
				EnclaveIdentityList: []types.EnclaveIdentity{
					{
						UniqueID: "0",
					},
					{
						UniqueID: "0",
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
