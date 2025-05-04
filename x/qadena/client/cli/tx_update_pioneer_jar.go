package cli

/*
import (
	"strconv"

	"qadena/x/qadena/types"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/spf13/cobra"

	qadenatx "qadena/x/qadena/client/tx"
	c "qadena/x/qadena/common"
)

var _ = strconv.Itoa(0)

func CmdUpdatePioneerJar() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update-pioneer-jar [pioneer-id] [jar-id]",
		Short: "Broadcast message UpdatePioneerJar",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			argPioneerID := args[0]
			argJarID := args[1]

			clientCtx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}

			msg := types.NewMsgUpdatePioneerJar(
				clientCtx.GetFromAddress().String(),
				argPioneerID,
				argJarID,
			)
			if err := msg.ValidateBasic(); err != nil {
				return err
			}
			err, res := qadenatx.GenerateOrBroadcastTxCLI(clientCtx, cmd.Flags(), msg)

			return c.CheckTxCLIResponse(clientCtx, err, res, "update pioneer jar")

		},
	}

	flags.AddTxFlagsToCmd(cmd)

	return cmd
}
*/
