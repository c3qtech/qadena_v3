package simulation

import (
	"math/rand"

	"qadena_v3/x/nameservice/keeper"
	"qadena_v3/x/nameservice/types"

	"github.com/cosmos/cosmos-sdk/baseapp"
	sdk "github.com/cosmos/cosmos-sdk/types"
	simtypes "github.com/cosmos/cosmos-sdk/types/simulation"
)

func SimulateMsgBindCredential(
	ak types.AccountKeeper,
	bk types.BankKeeper,
	k keeper.Keeper,
) simtypes.Operation {
	return func(r *rand.Rand, app *baseapp.BaseApp, ctx sdk.Context, accs []simtypes.Account, chainID string,
	) (simtypes.OperationMsg, []simtypes.FutureOperation, error) {
		simAccount, _ := simtypes.RandomAcc(r, accs)
		msg := &types.MsgBindCredential{
			Creator: simAccount.Address.String(),
		}

		// TODO: Handling the BindCredential simulation

		return simtypes.NoOpMsg(types.ModuleName, sdk.MsgTypeURL(msg), "BindCredential simulation not implemented"), nil, nil
	}
}
