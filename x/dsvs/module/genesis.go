package dsvs

import (
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/c3qtech/qadena_v3/x/dsvs/keeper"
	"github.com/c3qtech/qadena_v3/x/dsvs/types"
)

// InitGenesis initializes the module's state from a provided genesis state.
func InitGenesis(ctx sdk.Context, k keeper.Keeper, genState types.GenesisState) {
	// Set all the documentHash
	for _, elem := range genState.DocumentHashList {
		k.SetDocumentHash(ctx, elem)
	}
	// Set all the document
	for _, elem := range genState.DocumentList {
		k.SetDocument(ctx, elem)
	}
	// Set all the authorizedSignatory
	for _, elem := range genState.AuthorizedSignatoryList {
		k.SetAuthorizedSignatory(ctx, elem)
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

	genesis.DocumentHashList = k.GetAllDocumentHash(ctx)
	genesis.DocumentList = k.GetAllDocument(ctx)
	genesis.AuthorizedSignatoryList = k.GetAllAuthorizedSignatory(ctx)
	// this line is used by starport scaffolding # genesis/module/export

	return genesis
}
