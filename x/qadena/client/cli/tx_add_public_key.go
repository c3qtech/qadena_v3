package cli

import (
	"strconv"

	qadenatx "github.com/c3qtech/qadena_v3/x/qadena/client/tx"
	"github.com/c3qtech/qadena_v3/x/qadena/types"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/spf13/cobra"
)

var _ = strconv.Itoa(0)

func CmdAddPublicKey() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "add-public-key [pub-k] [pub-k-type]",
		Short: "Broadcast message AddPublicKey",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			argPubK := args[0]
			argPubKType := args[1]

			clientCtx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}

			//      fmt.Println("addr", clientCtx.GetFromAddress().String())

			msg := types.NewMsgAddPublicKey(
				clientCtx.GetFromAddress().String(),
				argPubK,
				argPubKType,
			)
			if err := msg.ValidateBasic(); err != nil {
				return err
			}

			err, _ = qadenatx.GenerateOrBroadcastTxCLISync(clientCtx, cmd.Flags(), "add public key", msg)

			return err
		},
	}

	flags.AddTxFlagsToCmd(cmd)

	return cmd
}
