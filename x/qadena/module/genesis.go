package qadena

import (
	sdk "github.com/cosmos/cosmos-sdk/types"

	"qadena_v3/x/qadena/keeper"
	"qadena_v3/x/qadena/types"
)

// InitGenesis initializes the module's state from a provided genesis state.
func InitGenesis(ctx sdk.Context, k keeper.Keeper, genState types.GenesisState) {
	// Set all the credential
	for _, elem := range genState.CredentialList {
		k.SetCredential(ctx, elem)
	}
	// Set all the publicKey
	for _, elem := range genState.PublicKeyList {
		k.SetPublicKey(ctx, elem)
	}
	// Set all the wallet
	for _, elem := range genState.WalletList {
		k.SetWallet(ctx, elem)
	}
	// Set all the intervalPublicKeyID
	for _, elem := range genState.IntervalPublicKeyIDList {
		k.SetIntervalPublicKeyID(ctx, elem)
	}
	// Set all the pioneerJar
	for _, elem := range genState.PioneerJarList {
		k.SetPioneerJar(ctx, elem)
	}
	// Set all the jarRegulator
	for _, elem := range genState.JarRegulatorList {
		k.SetJarRegulator(ctx, elem)
	}
	// Set all the suspiciousTransaction
	for _, elem := range genState.SuspiciousTransactionList {
		k.SetSuspiciousTransaction(ctx, elem)
	}

	// Set suspiciousTransaction count
	k.SetSuspiciousTransactionCount(ctx, genState.SuspiciousTransactionCount)
	// Set all the protectKey
	for _, elem := range genState.ProtectKeyList {
		k.SetProtectKey(ctx, elem)
	}
	// Set all the recoverKey
	for _, elem := range genState.RecoverKeyList {
		k.SetRecoverKey(ctx, elem)
	}
	// Set all the enclaveIdentity
	for _, elem := range genState.EnclaveIdentityList {
		k.SetEnclaveIdentity(ctx, elem)
	}
	// this line is used by starport scaffolding # genesis/module/init
	if err := k.SetParams(ctx, genState.Params); err != nil {
		panic(err)
	}
}

// ExportGenesis returns the module's exported genesis.
func ExportGenesis(ctx sdk.Context, k keeper.Keeper) *types.GenesisState {
	genesis := types.DefaultGenesis()
	genesis.Params = k.GetParams(ctx)

	genesis.CredentialList = k.GetAllCredential(ctx)
	genesis.PublicKeyList = k.GetAllPublicKey(ctx)
	genesis.WalletList = k.GetAllWallet(ctx)
	genesis.IntervalPublicKeyIDList = k.GetAllIntervalPublicKeyID(ctx)
	genesis.PioneerJarList = k.GetAllPioneerJar(ctx)
	genesis.JarRegulatorList = k.GetAllJarRegulator(ctx)
	genesis.SuspiciousTransactionList = k.GetAllSuspiciousTransaction(ctx)
	genesis.SuspiciousTransactionCount = k.GetSuspiciousTransactionCount(ctx)
	genesis.ProtectKeyList = k.GetAllProtectKey(ctx)
	genesis.RecoverKeyList = k.GetAllRecoverKey(ctx)
	genesis.EnclaveIdentityList = k.GetAllEnclaveIdentity(ctx)
	// this line is used by starport scaffolding # genesis/module/export

	return genesis
}
