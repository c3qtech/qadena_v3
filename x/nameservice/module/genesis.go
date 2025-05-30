package nameservice

import (
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/c3qtech/qadena_v3/x/nameservice/keeper"
	"github.com/c3qtech/qadena_v3/x/nameservice/types"
)

// InitGenesis initializes the module's state from a provided genesis state.
func InitGenesis(ctx sdk.Context, k keeper.Keeper, genState types.GenesisState) {
	// Set all the nameBinding
	for _, elem := range genState.NameBindingList {
		k.SetNameBinding(ctx, elem)
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

	genesis.NameBindingList = k.GetAllNameBinding(ctx)
	// this line is used by starport scaffolding # genesis/module/export

	return genesis
}
