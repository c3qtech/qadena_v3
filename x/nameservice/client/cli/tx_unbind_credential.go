package cli

import (
	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/spf13/cobra"

	nstypes "github.com/c3qtech/qadena_v3/x/nameservice/types"
	qadenatx "github.com/c3qtech/qadena_v3/x/qadena/client/tx"
	c "github.com/c3qtech/qadena_v3/x/qadena/common"
)

func CmdUnbindCredential() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "unbind-credential [credential-type e.g. phone-contact-info, email-contact-info] [credential-info e.g. the phone number or email being given up] [--from ephemeral-wallet-friendly-name]",
		Short: "Broadcast message UnbindCredential",
		Long: `Remove a name binding.

Bindings are keyed by the cleartext contact, so replacing a phone number or email address binds the
new value and leaves the old one still resolving to this wallet.  Run this for the old value so a
contact you no longer hold stops naming you.

Unlike bind-credential this takes the contact as an argument rather than reading it from a
credential: the usual reason to unbind is that the credential is already gone.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			argCredentialType := args[0]
			argCredentialInfo := args[1]

			ctx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}

			srcWalletID, _, _, _, err := c.GetAddress(ctx, ctx.GetFromAddress().String())
			if err != nil {
				return err
			}

			msg := nstypes.NewMsgUnbindCredential(
				srcWalletID,
				argCredentialType,
				argCredentialInfo,
			)
			if err := msg.ValidateBasic(); err != nil {
				return err
			}

			err, _ = qadenatx.GenerateOrBroadcastTxCLISync(ctx, cmd.Flags(), "unbind credential", msg)

			return err
		},
	}

	flags.AddTxFlagsToCmd(cmd)

	return cmd
}
