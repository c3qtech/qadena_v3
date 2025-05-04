package cli

import (
	"fmt"

	"strconv"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/spf13/cobra"

	dsvstypes "github.com/c3qtech/qadena_v3/x/dsvs/types"
	c "github.com/c3qtech/qadena_v3/x/qadena/common"

	qadenatx "github.com/c3qtech/qadena_v3/x/qadena/client/tx"
)

var _ = strconv.Itoa(0)

func CmdRemoveDocument() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remove-document [document-id]",
		Short: "Broadcast message RemoveDocument",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			argDocumentID := args[0]

			ctx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}

			// get source wallet ID, source public key in bytes, source public key and source private key hex
			srcWalletID, _, srcPubKey, _, err := c.GetAddress(ctx, ctx.GetFromAddress().String())
			if err != nil {
				return err
			}

			fmt.Println("srcWalletID", srcWalletID)
			fmt.Println("srcPubKey", srcPubKey)

			// remove a document
			msgRD := dsvstypes.MsgRemoveDocument{
				Creator:    ctx.GetFromAddress().String(),
				DocumentID: argDocumentID,
			}

			if err := msgRD.ValidateBasic(); err != nil {
				return err
			}

			err, _ = qadenatx.GenerateOrBroadcastTxCLISync(ctx, cmd.Flags(), "remove document", &msgRD)

			return err

		},
	}

	flags.AddTxFlagsToCmd(cmd)

	return cmd
}
