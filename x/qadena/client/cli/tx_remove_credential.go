package cli

import (
	"fmt"
	"strconv"

	qadenatx "github.com/c3qtech/qadena_v3/x/qadena/client/tx"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"
	"github.com/c3qtech/qadena_v3/x/qadena/types"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/spf13/cobra"
)

var _ = strconv.Itoa(0)

func CmdRemoveCredential() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remove-credential [credential-id] [(optional)credential-type] [--from provider-friendly-name e.g. secidentitysrvprv]",
		Short: "Broadcast message RemoveCredential",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			argCredentialID := args[0]
			argCredentialType := ""
			if len(args) > 1 {
				argCredentialType = args[1]
			}

			ctx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}

			fmt.Println("removing credential", argCredentialID, argCredentialType)

			// get source wallet ID, source public key in bytes, source public key and source private key hex
			srcWalletID, _, srcPubKey, _, err := c.GetAddress(ctx, ctx.GetFromAddress().String())
			if err != nil {
				return err
			}

			fmt.Println("srcWalletID", srcWalletID)
			fmt.Println("srcPubKey", srcPubKey)

			ccPubK := []c.VSharePubKInfo{
				{PubK: srcPubKey, NodeID: ctx.GetFromName(), NodeType: types.ServiceProviderNodeType},
			}

			ccPubK, err = c.ClientAppendRequiredChainCCPubK(ctx, ccPubK, "", false)
			if err != nil {
				return err
			}

			msgs := make([]sdk.Msg, 0)

			credentialTypes := []string{
				types.PersonalInfoCredentialType,
				types.FirstNamePersonalInfoCredentialType,
				types.MiddleNamePersonalInfoCredentialType,
				types.LastNamePersonalInfoCredentialType,
				types.PhoneContactCredentialType,
				types.EmailContactCredentialType,
			}

			if argCredentialType != "" {
				credentialTypes = []string{argCredentialType}
			}

			for _, credentialType := range credentialTypes {
				msgs = append(msgs, types.NewMsgRemoveCredential(ctx.GetFromAddress().String(), argCredentialID, credentialType))
			}

			fmt.Println("msg", c.PrettyPrint(msgs))

			err, _ = qadenatx.GenerateOrBroadcastTxCLISync(ctx, cmd.Flags(), "remove credential", msgs...)

			return err
		},
	}

	flags.AddTxFlagsToCmd(cmd)

	return cmd
}
