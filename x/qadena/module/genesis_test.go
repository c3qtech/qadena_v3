package qadena_test

import (
	"testing"

	keepertest "github.com/c3qtech/qadena_v3/testutil/keeper"
	"github.com/c3qtech/qadena_v3/testutil/nullify"
	qadena "github.com/c3qtech/qadena_v3/x/qadena/module"
	"github.com/c3qtech/qadena_v3/x/qadena/types"

	"github.com/stretchr/testify/require"
)

func TestGenesis(t *testing.T) {
	genesisState := types.GenesisState{
		Params: types.DefaultParams(),

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
			// Distinct, non-empty PubKIDs: the by-PubKID index is keyed on this alone, so leaving
			// them empty made both entries collide on the key "/" and the second tripped the
			// duplicate-PubKID panic.
			{
				NodeID:   "0",
				NodeType: "0",
				PubKID:   "pubkid0",
			},
			{
				NodeID:   "1",
				NodeType: "1",
				PubKID:   "pubkid1",
				// A record that has already rotated once.  Export -> import has to preserve this:
				// SetIntervalPublicKeyID derives PreviousPubKID from the store on a rotation, but a
				// genesis import is a FIRST write with no prior record to derive from, so the value
				// has to survive as supplied.  If it did not, every chain restarted from an exported
				// genesis would silently lose the rotation grace for one interval.
				PreviousPubKID: "pubkid1-previous",
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
		// this line is used by starport scaffolding # genesis/test/state
	}

	k, ctx := keepertest.QadenaKeeper(t)
	// InitGenesis writes through the keeper's Set* methods, every one of which forwards to the
	// enclave over gRPC.  There is no enclave here and the client is a nil package-level var, so
	// this panicked before reaching a single assertion.  The forward is skipped in CheckTx.
	ctx = ctx.WithIsCheckTx(true)
	qadena.InitGenesis(ctx, k, genesisState)
	got := qadena.ExportGenesis(ctx, k)
	require.NotNil(t, got)

	nullify.Fill(&genesisState)
	nullify.Fill(got)

	require.ElementsMatch(t, genesisState.CredentialList, got.CredentialList)
	require.ElementsMatch(t, genesisState.PublicKeyList, got.PublicKeyList)
	require.ElementsMatch(t, genesisState.WalletList, got.WalletList)
	require.ElementsMatch(t, genesisState.IntervalPublicKeyIDList, got.IntervalPublicKeyIDList)
	require.ElementsMatch(t, genesisState.PioneerJarList, got.PioneerJarList)
	require.ElementsMatch(t, genesisState.JarRegulatorList, got.JarRegulatorList)
	require.ElementsMatch(t, genesisState.SuspiciousTransactionList, got.SuspiciousTransactionList)
	require.Equal(t, genesisState.SuspiciousTransactionCount, got.SuspiciousTransactionCount)
	require.ElementsMatch(t, genesisState.ProtectKeyList, got.ProtectKeyList)
	require.ElementsMatch(t, genesisState.RecoverKeyList, got.RecoverKeyList)
	require.ElementsMatch(t, genesisState.EnclaveIdentityList, got.EnclaveIdentityList)
	// this line is used by starport scaffolding # genesis/test/assert
}
