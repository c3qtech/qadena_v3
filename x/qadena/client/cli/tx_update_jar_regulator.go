package cli

/*

import (
	"strconv"

	"github.com/c3qtech/qadena_v3/x/qadena/types"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/spf13/cobra"

	qadenatx "github.com/c3qtech/qadena_v3/x/qadena/client/tx"
	c "github.com/c3qtech/qadena_v3/x/qadena/common"
)

var _ = strconv.Itoa(0)

func CmdUpdateJarRegulator() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update-jar-regulator [jar-id] [regulator-id]",
		Short: "Broadcast message UpdateJarRegulator",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			argJarID := args[0]
			argRegulatorID := args[1]

			clientCtx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}

			msg := types.NewMsgUpdateJarRegulator(
				clientCtx.GetFromAddress().String(),
				argJarID,
				argRegulatorID,
			)
			if err := msg.ValidateBasic(); err != nil {
				return err
			}
			err, res := qadenatx.GenerateOrBroadcastTxCLI(clientCtx, cmd.Flags(), msg)

			return c.CheckTxCLIResponse(clientCtx, err, res, "update jar regulator")

		},
	}

	flags.AddTxFlagsToCmd(cmd)

	return cmd
}
*/
