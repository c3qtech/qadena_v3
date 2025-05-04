package cli

/*
import (
	"strconv"

	qadenatx "qadena/x/qadena/client/tx"
	c "qadena/x/qadena/common"
	"qadena/x/qadena/types"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/spf13/cobra"
)

var _ = strconv.Itoa(0)

func CmdUpdateIntervalPublicKeyId() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update-interval-public-key-id [node-id] [node-type] [optional:service-provider-type]",
		Short: "Broadcast message UpdateIntervalPublicKeyId",
		Args:  cobra.RangeArgs(2, 3),
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			argNodeID := args[0]
			argNodeType := args[1]
			argServiceProviderType := ""

			if len(args) == 3 {
				argServiceProviderType = args[2]
			}

			clientCtx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}

			msg := types.NewMsgUpdateIntervalPublicKeyID(
				clientCtx.GetFromAddress().String(),
				argNodeID,
				argNodeType,
				argServiceProviderType,
			)

			if err := msg.ValidateBasic(); err != nil {
				return err
			}
			err, res := qadenatx.GenerateOrBroadcastTxCLI(clientCtx, cmd.Flags(), msg)

			return c.CheckTxCLIResponse(clientCtx, err, res, "update interval public key id")
		},
	}

	flags.AddTxFlagsToCmd(cmd)

	return cmd
}
*/
