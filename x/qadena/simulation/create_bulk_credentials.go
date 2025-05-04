package simulation

import (
	"math/rand"

	"qadena_v3/x/qadena/keeper"
	"qadena_v3/x/qadena/types"

	"github.com/cosmos/cosmos-sdk/baseapp"
	sdk "github.com/cosmos/cosmos-sdk/types"
	simtypes "github.com/cosmos/cosmos-sdk/types/simulation"
)

func SimulateMsgCreateBulkCredentials(
	ak types.AccountKeeper,
	bk types.BankKeeper,
	k keeper.Keeper,
) simtypes.Operation {
	return func(r *rand.Rand, app *baseapp.BaseApp, ctx sdk.Context, accs []simtypes.Account, chainID string,
	) (simtypes.OperationMsg, []simtypes.FutureOperation, error) {
		simAccount, _ := simtypes.RandomAcc(r, accs)
		msg := &types.MsgCreateBulkCredentials{
			Creator: simAccount.Address.String(),
		}

		// TODO: Handling the CreateBulkCredentials simulation

		return simtypes.NoOpMsg(types.ModuleName, sdk.MsgTypeURL(msg), "CreateBulkCredentials simulation not implemented"), nil, nil
	}
}
