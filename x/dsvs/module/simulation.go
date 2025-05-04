package dsvs

import (
	"math/rand"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/module"
	simtypes "github.com/cosmos/cosmos-sdk/types/simulation"
	"github.com/cosmos/cosmos-sdk/x/simulation"

	"qadena/testutil/sample"
	dsvssimulation "qadena/x/dsvs/simulation"
	"qadena/x/dsvs/types"
)

// avoid unused import issue
var (
	_ = dsvssimulation.FindAccount
	_ = rand.Rand{}
	_ = sample.AccAddress
	_ = sdk.AccAddress{}
	_ = simulation.MsgEntryKind
)

const (
	opWeightMsgCreateDocument = "op_weight_msg_create_document"
	// TODO: Determine the simulation weight value
	defaultWeightMsgCreateDocument int = 100

	opWeightMsgSignDocument = "op_weight_msg_sign_document"
	// TODO: Determine the simulation weight value
	defaultWeightMsgSignDocument int = 100

	opWeightMsgRegisterAuthorizedSignatory = "op_weight_msg_register_authorized_signatory"
	// TODO: Determine the simulation weight value
	defaultWeightMsgRegisterAuthorizedSignatory int = 100

	opWeightMsgRemoveDocument = "op_weight_msg_remove_document"
	// TODO: Determine the simulation weight value
	defaultWeightMsgRemoveDocument int = 100

	// this line is used by starport scaffolding # simapp/module/const
)

// GenerateGenesisState creates a randomized GenState of the module.
func (AppModule) GenerateGenesisState(simState *module.SimulationState) {
	accs := make([]string, len(simState.Accounts))
	for i, acc := range simState.Accounts {
		accs[i] = acc.Address.String()
	}
	dsvsGenesis := types.GenesisState{
		Params: types.DefaultParams(),
		// this line is used by starport scaffolding # simapp/module/genesisState
	}
	simState.GenState[types.ModuleName] = simState.Cdc.MustMarshalJSON(&dsvsGenesis)
}

// RegisterStoreDecoder registers a decoder.
func (am AppModule) RegisterStoreDecoder(_ simtypes.StoreDecoderRegistry) {}

// WeightedOperations returns the all the gov module operations with their respective weights.
func (am AppModule) WeightedOperations(simState module.SimulationState) []simtypes.WeightedOperation {
	operations := make([]simtypes.WeightedOperation, 0)

	var weightMsgCreateDocument int
	simState.AppParams.GetOrGenerate(opWeightMsgCreateDocument, &weightMsgCreateDocument, nil,
		func(_ *rand.Rand) {
			weightMsgCreateDocument = defaultWeightMsgCreateDocument
		},
	)
	operations = append(operations, simulation.NewWeightedOperation(
		weightMsgCreateDocument,
		dsvssimulation.SimulateMsgCreateDocument(am.accountKeeper, am.bankKeeper, am.keeper),
	))

	var weightMsgSignDocument int
	simState.AppParams.GetOrGenerate(opWeightMsgSignDocument, &weightMsgSignDocument, nil,
		func(_ *rand.Rand) {
			weightMsgSignDocument = defaultWeightMsgSignDocument
		},
	)
	operations = append(operations, simulation.NewWeightedOperation(
		weightMsgSignDocument,
		dsvssimulation.SimulateMsgSignDocument(am.accountKeeper, am.bankKeeper, am.keeper),
	))

	var weightMsgRegisterAuthorizedSignatory int
	simState.AppParams.GetOrGenerate(opWeightMsgRegisterAuthorizedSignatory, &weightMsgRegisterAuthorizedSignatory, nil,
		func(_ *rand.Rand) {
			weightMsgRegisterAuthorizedSignatory = defaultWeightMsgRegisterAuthorizedSignatory
		},
	)
	operations = append(operations, simulation.NewWeightedOperation(
		weightMsgRegisterAuthorizedSignatory,
		dsvssimulation.SimulateMsgRegisterAuthorizedSignatory(am.accountKeeper, am.bankKeeper, am.keeper),
	))

	var weightMsgRemoveDocument int
	simState.AppParams.GetOrGenerate(opWeightMsgRemoveDocument, &weightMsgRemoveDocument, nil,
		func(_ *rand.Rand) {
			weightMsgRemoveDocument = defaultWeightMsgRemoveDocument
		},
	)
	operations = append(operations, simulation.NewWeightedOperation(
		weightMsgRemoveDocument,
		dsvssimulation.SimulateMsgRemoveDocument(am.accountKeeper, am.bankKeeper, am.keeper),
	))

	// this line is used by starport scaffolding # simapp/module/operation

	return operations
}

// ProposalMsgs returns msgs used for governance proposals for simulations.
func (am AppModule) ProposalMsgs(simState module.SimulationState) []simtypes.WeightedProposalMsg {
	return []simtypes.WeightedProposalMsg{
		simulation.NewWeightedProposalMsg(
			opWeightMsgCreateDocument,
			defaultWeightMsgCreateDocument,
			func(r *rand.Rand, ctx sdk.Context, accs []simtypes.Account) sdk.Msg {
				dsvssimulation.SimulateMsgCreateDocument(am.accountKeeper, am.bankKeeper, am.keeper)
				return nil
			},
		),
		simulation.NewWeightedProposalMsg(
			opWeightMsgSignDocument,
			defaultWeightMsgSignDocument,
			func(r *rand.Rand, ctx sdk.Context, accs []simtypes.Account) sdk.Msg {
				dsvssimulation.SimulateMsgSignDocument(am.accountKeeper, am.bankKeeper, am.keeper)
				return nil
			},
		),
		simulation.NewWeightedProposalMsg(
			opWeightMsgRegisterAuthorizedSignatory,
			defaultWeightMsgRegisterAuthorizedSignatory,
			func(r *rand.Rand, ctx sdk.Context, accs []simtypes.Account) sdk.Msg {
				dsvssimulation.SimulateMsgRegisterAuthorizedSignatory(am.accountKeeper, am.bankKeeper, am.keeper)
				return nil
			},
		),
		simulation.NewWeightedProposalMsg(
			opWeightMsgRemoveDocument,
			defaultWeightMsgRemoveDocument,
			func(r *rand.Rand, ctx sdk.Context, accs []simtypes.Account) sdk.Msg {
				dsvssimulation.SimulateMsgRemoveDocument(am.accountKeeper, am.bankKeeper, am.keeper)
				return nil
			},
		),
		// this line is used by starport scaffolding # simapp/module/OpMsg
	}
}
