package qadena

import (
	"math/rand"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/module"
	simtypes "github.com/cosmos/cosmos-sdk/types/simulation"
	"github.com/cosmos/cosmos-sdk/x/simulation"

	"github.com/c3qtech/qadena_v3/testutil/sample"
	qadenasimulation "github.com/c3qtech/qadena_v3/x/qadena/simulation"
	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

// avoid unused import issue
var (
	_ = qadenasimulation.FindAccount
	_ = rand.Rand{}
	_ = sample.AccAddress
	_ = sdk.AccAddress{}
	_ = simulation.MsgEntryKind
)

const (
	opWeightMsgCreateSuspiciousTransaction = "op_weight_msg_suspicious_transaction"
	// TODO: Determine the simulation weight value
	defaultWeightMsgCreateSuspiciousTransaction int = 100

	opWeightMsgUpdateSuspiciousTransaction = "op_weight_msg_suspicious_transaction"
	// TODO: Determine the simulation weight value
	defaultWeightMsgUpdateSuspiciousTransaction int = 100

	opWeightMsgDeleteSuspiciousTransaction = "op_weight_msg_suspicious_transaction"
	// TODO: Determine the simulation weight value
	defaultWeightMsgDeleteSuspiciousTransaction int = 100

	opWeightMsgAddPublicKey = "op_weight_msg_add_public_key"
	// TODO: Determine the simulation weight value
	defaultWeightMsgAddPublicKey int = 100

	opWeightMsgUpdateIntervalPublicKeyID = "op_weight_msg_update_interval_public_key_i_d"
	// TODO: Determine the simulation weight value
	defaultWeightMsgUpdateIntervalPublicKeyID int = 100

	opWeightMsgUpdatePioneerJar = "op_weight_msg_update_pioneer_jar"
	// TODO: Determine the simulation weight value
	defaultWeightMsgUpdatePioneerJar int = 100

	opWeightMsgUpdateJarRegulator = "op_weight_msg_update_jar_regulator"
	// TODO: Determine the simulation weight value
	defaultWeightMsgUpdateJarRegulator int = 100

	opWeightMsgCreateWallet = "op_weight_msg_create_wallet"
	// TODO: Determine the simulation weight value
	defaultWeightMsgCreateWallet int = 100

	opWeightMsgTransferFunds = "op_weight_msg_transfer_funds"
	// TODO: Determine the simulation weight value
	defaultWeightMsgTransferFunds int = 100

	opWeightMsgReceiveFunds = "op_weight_msg_receive_funds"
	// TODO: Determine the simulation weight value
	defaultWeightMsgReceiveFunds int = 100

	opWeightMsgDeploySmartContract = "op_weight_msg_deploy_smart_contract"
	// TODO: Determine the simulation weight value
	defaultWeightMsgDeploySmartContract int = 100

	opWeightMsgExecuteSmartContract = "op_weight_msg_execute_smart_contract"
	// TODO: Determine the simulation weight value
	defaultWeightMsgExecuteSmartContract int = 100

	opWeightMsgCreateCredential = "op_weight_msg_create_credential"
	// TODO: Determine the simulation weight value
	defaultWeightMsgCreateCredential int = 100

	opWeightMsgPioneerAddPublicKey = "op_weight_msg_pioneer_add_public_key"
	// TODO: Determine the simulation weight value
	defaultWeightMsgPioneerAddPublicKey int = 100

	opWeightMsgPioneerUpdateIntervalPublicKeyID = "op_weight_msg_pioneer_update_interval_public_key_i_d"
	// TODO: Determine the simulation weight value
	defaultWeightMsgPioneerUpdateIntervalPublicKeyID int = 100

	opWeightMsgPioneerEnclaveExchange = "op_weight_msg_pioneer_enclave_exchange"
	// TODO: Determine the simulation weight value
	defaultWeightMsgPioneerEnclaveExchange int = 100

	opWeightMsgPioneerBroadcastSecretSharePrivateKey = "op_weight_msg_pioneer_broadcast_secret_share_private_key"
	// TODO: Determine the simulation weight value
	defaultWeightMsgPioneerBroadcastSecretSharePrivateKey int = 100

	opWeightMsgProtectPrivateKey = "op_weight_msg_protect_private_key"
	// TODO: Determine the simulation weight value
	defaultWeightMsgProtectPrivateKey int = 100

	opWeightMsgSignRecoverPrivateKey = "op_weight_msg_sign_recover_private_key"
	// TODO: Determine the simulation weight value
	defaultWeightMsgSignRecoverPrivateKey int = 100

	opWeightMsgClaimCredential = "op_weight_msg_claim_credential"
	// TODO: Determine the simulation weight value
	defaultWeightMsgClaimCredential int = 100

	opWeightMsgCreateBulkCredentials = "op_weight_msg_create_bulk_credentials"
	// TODO: Determine the simulation weight value
	defaultWeightMsgCreateBulkCredentials int = 100

	// this line is used by starport scaffolding # simapp/module/const
)

// GenerateGenesisState creates a randomized GenState of the module.
func (AppModule) GenerateGenesisState(simState *module.SimulationState) {
	accs := make([]string, len(simState.Accounts))
	for i, acc := range simState.Accounts {
		accs[i] = acc.Address.String()
	}
	qadenaGenesis := types.GenesisState{
		Params: types.DefaultParams(),
		SuspiciousTransactionList: []types.SuspiciousTransaction{
			{
				Id:      0,
				Creator: sample.AccAddress(),
			},
			{
				Id:      1,
				Creator: sample.AccAddress(),
			},
		},
		SuspiciousTransactionCount: 2,
		// this line is used by starport scaffolding # simapp/module/genesisState
	}
	simState.GenState[types.ModuleName] = simState.Cdc.MustMarshalJSON(&qadenaGenesis)
}

// RegisterStoreDecoder registers a decoder.
func (am AppModule) RegisterStoreDecoder(_ simtypes.StoreDecoderRegistry) {}

// WeightedOperations returns the all the gov module operations with their respective weights.
func (am AppModule) WeightedOperations(simState module.SimulationState) []simtypes.WeightedOperation {
	operations := make([]simtypes.WeightedOperation, 0)

	var weightMsgCreateSuspiciousTransaction int
	simState.AppParams.GetOrGenerate(opWeightMsgCreateSuspiciousTransaction, &weightMsgCreateSuspiciousTransaction, nil,
		func(_ *rand.Rand) {
			weightMsgCreateSuspiciousTransaction = defaultWeightMsgCreateSuspiciousTransaction
		},
	)
	operations = append(operations, simulation.NewWeightedOperation(
		weightMsgCreateSuspiciousTransaction,
		qadenasimulation.SimulateMsgCreateSuspiciousTransaction(am.accountKeeper, am.bankKeeper, am.keeper),
	))

	var weightMsgUpdateSuspiciousTransaction int
	simState.AppParams.GetOrGenerate(opWeightMsgUpdateSuspiciousTransaction, &weightMsgUpdateSuspiciousTransaction, nil,
		func(_ *rand.Rand) {
			weightMsgUpdateSuspiciousTransaction = defaultWeightMsgUpdateSuspiciousTransaction
		},
	)
	operations = append(operations, simulation.NewWeightedOperation(
		weightMsgUpdateSuspiciousTransaction,
		qadenasimulation.SimulateMsgUpdateSuspiciousTransaction(am.accountKeeper, am.bankKeeper, am.keeper),
	))

	var weightMsgDeleteSuspiciousTransaction int
	simState.AppParams.GetOrGenerate(opWeightMsgDeleteSuspiciousTransaction, &weightMsgDeleteSuspiciousTransaction, nil,
		func(_ *rand.Rand) {
			weightMsgDeleteSuspiciousTransaction = defaultWeightMsgDeleteSuspiciousTransaction
		},
	)
	operations = append(operations, simulation.NewWeightedOperation(
		weightMsgDeleteSuspiciousTransaction,
		qadenasimulation.SimulateMsgDeleteSuspiciousTransaction(am.accountKeeper, am.bankKeeper, am.keeper),
	))

	var weightMsgAddPublicKey int
	simState.AppParams.GetOrGenerate(opWeightMsgAddPublicKey, &weightMsgAddPublicKey, nil,
		func(_ *rand.Rand) {
			weightMsgAddPublicKey = defaultWeightMsgAddPublicKey
		},
	)
	operations = append(operations, simulation.NewWeightedOperation(
		weightMsgAddPublicKey,
		qadenasimulation.SimulateMsgAddPublicKey(am.accountKeeper, am.bankKeeper, am.keeper),
	))

	var weightMsgUpdateIntervalPublicKeyID int
	simState.AppParams.GetOrGenerate(opWeightMsgUpdateIntervalPublicKeyID, &weightMsgUpdateIntervalPublicKeyID, nil,
		func(_ *rand.Rand) {
			weightMsgUpdateIntervalPublicKeyID = defaultWeightMsgUpdateIntervalPublicKeyID
		},
	)
	operations = append(operations, simulation.NewWeightedOperation(
		weightMsgUpdateIntervalPublicKeyID,
		qadenasimulation.SimulateMsgUpdateIntervalPublicKeyID(am.accountKeeper, am.bankKeeper, am.keeper),
	))

	var weightMsgUpdatePioneerJar int
	simState.AppParams.GetOrGenerate(opWeightMsgUpdatePioneerJar, &weightMsgUpdatePioneerJar, nil,
		func(_ *rand.Rand) {
			weightMsgUpdatePioneerJar = defaultWeightMsgUpdatePioneerJar
		},
	)
	operations = append(operations, simulation.NewWeightedOperation(
		weightMsgUpdatePioneerJar,
		qadenasimulation.SimulateMsgUpdatePioneerJar(am.accountKeeper, am.bankKeeper, am.keeper),
	))

	var weightMsgUpdateJarRegulator int
	simState.AppParams.GetOrGenerate(opWeightMsgUpdateJarRegulator, &weightMsgUpdateJarRegulator, nil,
		func(_ *rand.Rand) {
			weightMsgUpdateJarRegulator = defaultWeightMsgUpdateJarRegulator
		},
	)
	operations = append(operations, simulation.NewWeightedOperation(
		weightMsgUpdateJarRegulator,
		qadenasimulation.SimulateMsgUpdateJarRegulator(am.accountKeeper, am.bankKeeper, am.keeper),
	))

	var weightMsgCreateWallet int
	simState.AppParams.GetOrGenerate(opWeightMsgCreateWallet, &weightMsgCreateWallet, nil,
		func(_ *rand.Rand) {
			weightMsgCreateWallet = defaultWeightMsgCreateWallet
		},
	)
	operations = append(operations, simulation.NewWeightedOperation(
		weightMsgCreateWallet,
		qadenasimulation.SimulateMsgCreateWallet(am.accountKeeper, am.bankKeeper, am.keeper),
	))

	var weightMsgTransferFunds int
	simState.AppParams.GetOrGenerate(opWeightMsgTransferFunds, &weightMsgTransferFunds, nil,
		func(_ *rand.Rand) {
			weightMsgTransferFunds = defaultWeightMsgTransferFunds
		},
	)
	operations = append(operations, simulation.NewWeightedOperation(
		weightMsgTransferFunds,
		qadenasimulation.SimulateMsgTransferFunds(am.accountKeeper, am.bankKeeper, am.keeper),
	))

	var weightMsgReceiveFunds int
	simState.AppParams.GetOrGenerate(opWeightMsgReceiveFunds, &weightMsgReceiveFunds, nil,
		func(_ *rand.Rand) {
			weightMsgReceiveFunds = defaultWeightMsgReceiveFunds
		},
	)
	operations = append(operations, simulation.NewWeightedOperation(
		weightMsgReceiveFunds,
		qadenasimulation.SimulateMsgReceiveFunds(am.accountKeeper, am.bankKeeper, am.keeper),
	))

	var weightMsgDeploySmartContract int
	simState.AppParams.GetOrGenerate(opWeightMsgDeploySmartContract, &weightMsgDeploySmartContract, nil,
		func(_ *rand.Rand) {
			weightMsgDeploySmartContract = defaultWeightMsgDeploySmartContract
		},
	)
	operations = append(operations, simulation.NewWeightedOperation(
		weightMsgDeploySmartContract,
		qadenasimulation.SimulateMsgDeploySmartContract(am.accountKeeper, am.bankKeeper, am.keeper),
	))

	var weightMsgExecuteSmartContract int
	simState.AppParams.GetOrGenerate(opWeightMsgExecuteSmartContract, &weightMsgExecuteSmartContract, nil,
		func(_ *rand.Rand) {
			weightMsgExecuteSmartContract = defaultWeightMsgExecuteSmartContract
		},
	)
	operations = append(operations, simulation.NewWeightedOperation(
		weightMsgExecuteSmartContract,
		qadenasimulation.SimulateMsgExecuteSmartContract(am.accountKeeper, am.bankKeeper, am.keeper),
	))

	var weightMsgCreateCredential int
	simState.AppParams.GetOrGenerate(opWeightMsgCreateCredential, &weightMsgCreateCredential, nil,
		func(_ *rand.Rand) {
			weightMsgCreateCredential = defaultWeightMsgCreateCredential
		},
	)
	operations = append(operations, simulation.NewWeightedOperation(
		weightMsgCreateCredential,
		qadenasimulation.SimulateMsgCreateCredential(am.accountKeeper, am.bankKeeper, am.keeper),
	))

	var weightMsgPioneerAddPublicKey int
	simState.AppParams.GetOrGenerate(opWeightMsgPioneerAddPublicKey, &weightMsgPioneerAddPublicKey, nil,
		func(_ *rand.Rand) {
			weightMsgPioneerAddPublicKey = defaultWeightMsgPioneerAddPublicKey
		},
	)
	operations = append(operations, simulation.NewWeightedOperation(
		weightMsgPioneerAddPublicKey,
		qadenasimulation.SimulateMsgPioneerAddPublicKey(am.accountKeeper, am.bankKeeper, am.keeper),
	))

	var weightMsgPioneerUpdateIntervalPublicKeyID int
	simState.AppParams.GetOrGenerate(opWeightMsgPioneerUpdateIntervalPublicKeyID, &weightMsgPioneerUpdateIntervalPublicKeyID, nil,
		func(_ *rand.Rand) {
			weightMsgPioneerUpdateIntervalPublicKeyID = defaultWeightMsgPioneerUpdateIntervalPublicKeyID
		},
	)
	operations = append(operations, simulation.NewWeightedOperation(
		weightMsgPioneerUpdateIntervalPublicKeyID,
		qadenasimulation.SimulateMsgPioneerUpdateIntervalPublicKeyID(am.accountKeeper, am.bankKeeper, am.keeper),
	))

	var weightMsgPioneerEnclaveExchange int
	simState.AppParams.GetOrGenerate(opWeightMsgPioneerEnclaveExchange, &weightMsgPioneerEnclaveExchange, nil,
		func(_ *rand.Rand) {
			weightMsgPioneerEnclaveExchange = defaultWeightMsgPioneerEnclaveExchange
		},
	)
	operations = append(operations, simulation.NewWeightedOperation(
		weightMsgPioneerEnclaveExchange,
		qadenasimulation.SimulateMsgPioneerEnclaveExchange(am.accountKeeper, am.bankKeeper, am.keeper),
	))

	var weightMsgPioneerBroadcastSecretSharePrivateKey int
	simState.AppParams.GetOrGenerate(opWeightMsgPioneerBroadcastSecretSharePrivateKey, &weightMsgPioneerBroadcastSecretSharePrivateKey, nil,
		func(_ *rand.Rand) {
			weightMsgPioneerBroadcastSecretSharePrivateKey = defaultWeightMsgPioneerBroadcastSecretSharePrivateKey
		},
	)
	operations = append(operations, simulation.NewWeightedOperation(
		weightMsgPioneerBroadcastSecretSharePrivateKey,
		qadenasimulation.SimulateMsgPioneerBroadcastSecretSharePrivateKey(am.accountKeeper, am.bankKeeper, am.keeper),
	))

	var weightMsgProtectPrivateKey int
	simState.AppParams.GetOrGenerate(opWeightMsgProtectPrivateKey, &weightMsgProtectPrivateKey, nil,
		func(_ *rand.Rand) {
			weightMsgProtectPrivateKey = defaultWeightMsgProtectPrivateKey
		},
	)
	operations = append(operations, simulation.NewWeightedOperation(
		weightMsgProtectPrivateKey,
		qadenasimulation.SimulateMsgProtectPrivateKey(am.accountKeeper, am.bankKeeper, am.keeper),
	))

	var weightMsgSignRecoverPrivateKey int
	simState.AppParams.GetOrGenerate(opWeightMsgSignRecoverPrivateKey, &weightMsgSignRecoverPrivateKey, nil,
		func(_ *rand.Rand) {
			weightMsgSignRecoverPrivateKey = defaultWeightMsgSignRecoverPrivateKey
		},
	)
	operations = append(operations, simulation.NewWeightedOperation(
		weightMsgSignRecoverPrivateKey,
		qadenasimulation.SimulateMsgSignRecoverPrivateKey(am.accountKeeper, am.bankKeeper, am.keeper),
	))

	var weightMsgClaimCredential int
	simState.AppParams.GetOrGenerate(opWeightMsgClaimCredential, &weightMsgClaimCredential, nil,
		func(_ *rand.Rand) {
			weightMsgClaimCredential = defaultWeightMsgClaimCredential
		},
	)
	operations = append(operations, simulation.NewWeightedOperation(
		weightMsgClaimCredential,
		qadenasimulation.SimulateMsgClaimCredential(am.accountKeeper, am.bankKeeper, am.keeper),
	))

	var weightMsgCreateBulkCredentials int
	simState.AppParams.GetOrGenerate(opWeightMsgCreateBulkCredentials, &weightMsgCreateBulkCredentials, nil,
		func(_ *rand.Rand) {
			weightMsgCreateBulkCredentials = defaultWeightMsgCreateBulkCredentials
		},
	)
	operations = append(operations, simulation.NewWeightedOperation(
		weightMsgCreateBulkCredentials,
		qadenasimulation.SimulateMsgCreateBulkCredentials(am.accountKeeper, am.bankKeeper, am.keeper),
	))

	// this line is used by starport scaffolding # simapp/module/operation

	return operations
}

// ProposalMsgs returns msgs used for governance proposals for simulations.
func (am AppModule) ProposalMsgs(simState module.SimulationState) []simtypes.WeightedProposalMsg {
	return []simtypes.WeightedProposalMsg{
		simulation.NewWeightedProposalMsg(
			opWeightMsgCreateSuspiciousTransaction,
			defaultWeightMsgCreateSuspiciousTransaction,
			func(r *rand.Rand, ctx sdk.Context, accs []simtypes.Account) sdk.Msg {
				qadenasimulation.SimulateMsgCreateSuspiciousTransaction(am.accountKeeper, am.bankKeeper, am.keeper)
				return nil
			},
		),
		simulation.NewWeightedProposalMsg(
			opWeightMsgUpdateSuspiciousTransaction,
			defaultWeightMsgUpdateSuspiciousTransaction,
			func(r *rand.Rand, ctx sdk.Context, accs []simtypes.Account) sdk.Msg {
				qadenasimulation.SimulateMsgUpdateSuspiciousTransaction(am.accountKeeper, am.bankKeeper, am.keeper)
				return nil
			},
		),
		simulation.NewWeightedProposalMsg(
			opWeightMsgDeleteSuspiciousTransaction,
			defaultWeightMsgDeleteSuspiciousTransaction,
			func(r *rand.Rand, ctx sdk.Context, accs []simtypes.Account) sdk.Msg {
				qadenasimulation.SimulateMsgDeleteSuspiciousTransaction(am.accountKeeper, am.bankKeeper, am.keeper)
				return nil
			},
		),
		simulation.NewWeightedProposalMsg(
			opWeightMsgAddPublicKey,
			defaultWeightMsgAddPublicKey,
			func(r *rand.Rand, ctx sdk.Context, accs []simtypes.Account) sdk.Msg {
				qadenasimulation.SimulateMsgAddPublicKey(am.accountKeeper, am.bankKeeper, am.keeper)
				return nil
			},
		),
		simulation.NewWeightedProposalMsg(
			opWeightMsgUpdateIntervalPublicKeyID,
			defaultWeightMsgUpdateIntervalPublicKeyID,
			func(r *rand.Rand, ctx sdk.Context, accs []simtypes.Account) sdk.Msg {
				qadenasimulation.SimulateMsgUpdateIntervalPublicKeyID(am.accountKeeper, am.bankKeeper, am.keeper)
				return nil
			},
		),
		simulation.NewWeightedProposalMsg(
			opWeightMsgUpdatePioneerJar,
			defaultWeightMsgUpdatePioneerJar,
			func(r *rand.Rand, ctx sdk.Context, accs []simtypes.Account) sdk.Msg {
				qadenasimulation.SimulateMsgUpdatePioneerJar(am.accountKeeper, am.bankKeeper, am.keeper)
				return nil
			},
		),
		simulation.NewWeightedProposalMsg(
			opWeightMsgUpdateJarRegulator,
			defaultWeightMsgUpdateJarRegulator,
			func(r *rand.Rand, ctx sdk.Context, accs []simtypes.Account) sdk.Msg {
				qadenasimulation.SimulateMsgUpdateJarRegulator(am.accountKeeper, am.bankKeeper, am.keeper)
				return nil
			},
		),
		simulation.NewWeightedProposalMsg(
			opWeightMsgCreateWallet,
			defaultWeightMsgCreateWallet,
			func(r *rand.Rand, ctx sdk.Context, accs []simtypes.Account) sdk.Msg {
				qadenasimulation.SimulateMsgCreateWallet(am.accountKeeper, am.bankKeeper, am.keeper)
				return nil
			},
		),
		simulation.NewWeightedProposalMsg(
			opWeightMsgTransferFunds,
			defaultWeightMsgTransferFunds,
			func(r *rand.Rand, ctx sdk.Context, accs []simtypes.Account) sdk.Msg {
				qadenasimulation.SimulateMsgTransferFunds(am.accountKeeper, am.bankKeeper, am.keeper)
				return nil
			},
		),
		simulation.NewWeightedProposalMsg(
			opWeightMsgReceiveFunds,
			defaultWeightMsgReceiveFunds,
			func(r *rand.Rand, ctx sdk.Context, accs []simtypes.Account) sdk.Msg {
				qadenasimulation.SimulateMsgReceiveFunds(am.accountKeeper, am.bankKeeper, am.keeper)
				return nil
			},
		),
		simulation.NewWeightedProposalMsg(
			opWeightMsgDeploySmartContract,
			defaultWeightMsgDeploySmartContract,
			func(r *rand.Rand, ctx sdk.Context, accs []simtypes.Account) sdk.Msg {
				qadenasimulation.SimulateMsgDeploySmartContract(am.accountKeeper, am.bankKeeper, am.keeper)
				return nil
			},
		),
		simulation.NewWeightedProposalMsg(
			opWeightMsgExecuteSmartContract,
			defaultWeightMsgExecuteSmartContract,
			func(r *rand.Rand, ctx sdk.Context, accs []simtypes.Account) sdk.Msg {
				qadenasimulation.SimulateMsgExecuteSmartContract(am.accountKeeper, am.bankKeeper, am.keeper)
				return nil
			},
		),
		simulation.NewWeightedProposalMsg(
			opWeightMsgCreateCredential,
			defaultWeightMsgCreateCredential,
			func(r *rand.Rand, ctx sdk.Context, accs []simtypes.Account) sdk.Msg {
				qadenasimulation.SimulateMsgCreateCredential(am.accountKeeper, am.bankKeeper, am.keeper)
				return nil
			},
		),
		simulation.NewWeightedProposalMsg(
			opWeightMsgPioneerAddPublicKey,
			defaultWeightMsgPioneerAddPublicKey,
			func(r *rand.Rand, ctx sdk.Context, accs []simtypes.Account) sdk.Msg {
				qadenasimulation.SimulateMsgPioneerAddPublicKey(am.accountKeeper, am.bankKeeper, am.keeper)
				return nil
			},
		),
		simulation.NewWeightedProposalMsg(
			opWeightMsgPioneerUpdateIntervalPublicKeyID,
			defaultWeightMsgPioneerUpdateIntervalPublicKeyID,
			func(r *rand.Rand, ctx sdk.Context, accs []simtypes.Account) sdk.Msg {
				qadenasimulation.SimulateMsgPioneerUpdateIntervalPublicKeyID(am.accountKeeper, am.bankKeeper, am.keeper)
				return nil
			},
		),
		simulation.NewWeightedProposalMsg(
			opWeightMsgPioneerEnclaveExchange,
			defaultWeightMsgPioneerEnclaveExchange,
			func(r *rand.Rand, ctx sdk.Context, accs []simtypes.Account) sdk.Msg {
				qadenasimulation.SimulateMsgPioneerEnclaveExchange(am.accountKeeper, am.bankKeeper, am.keeper)
				return nil
			},
		),
		simulation.NewWeightedProposalMsg(
			opWeightMsgPioneerBroadcastSecretSharePrivateKey,
			defaultWeightMsgPioneerBroadcastSecretSharePrivateKey,
			func(r *rand.Rand, ctx sdk.Context, accs []simtypes.Account) sdk.Msg {
				qadenasimulation.SimulateMsgPioneerBroadcastSecretSharePrivateKey(am.accountKeeper, am.bankKeeper, am.keeper)
				return nil
			},
		),
		simulation.NewWeightedProposalMsg(
			opWeightMsgProtectPrivateKey,
			defaultWeightMsgProtectPrivateKey,
			func(r *rand.Rand, ctx sdk.Context, accs []simtypes.Account) sdk.Msg {
				qadenasimulation.SimulateMsgProtectPrivateKey(am.accountKeeper, am.bankKeeper, am.keeper)
				return nil
			},
		),
		simulation.NewWeightedProposalMsg(
			opWeightMsgSignRecoverPrivateKey,
			defaultWeightMsgSignRecoverPrivateKey,
			func(r *rand.Rand, ctx sdk.Context, accs []simtypes.Account) sdk.Msg {
				qadenasimulation.SimulateMsgSignRecoverPrivateKey(am.accountKeeper, am.bankKeeper, am.keeper)
				return nil
			},
		),
		simulation.NewWeightedProposalMsg(
			opWeightMsgClaimCredential,
			defaultWeightMsgClaimCredential,
			func(r *rand.Rand, ctx sdk.Context, accs []simtypes.Account) sdk.Msg {
				qadenasimulation.SimulateMsgClaimCredential(am.accountKeeper, am.bankKeeper, am.keeper)
				return nil
			},
		),
		simulation.NewWeightedProposalMsg(
			opWeightMsgCreateBulkCredentials,
			defaultWeightMsgCreateBulkCredentials,
			func(r *rand.Rand, ctx sdk.Context, accs []simtypes.Account) sdk.Msg {
				qadenasimulation.SimulateMsgCreateBulkCredentials(am.accountKeeper, am.bankKeeper, am.keeper)
				return nil
			},
		),
		// this line is used by starport scaffolding # simapp/module/OpMsg
	}
}
