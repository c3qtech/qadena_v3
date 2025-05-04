package cli

import (
	"context"

	dsvstypes "qadena_v3/x/dsvs/types"
	"qadena_v3/x/qadena/types"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/spf13/cobra"

	"fmt"
	c "qadena_v3/x/qadena/common"
)

func CmdListAuthorizedSignatory() *cobra.Command {
	var argDecryptAs string

	cmd := &cobra.Command{
		Use:   "list-authorized-signatory",
		Short: "list all Authorized Signatories",
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx := client.GetClientContextFromCmd(cmd)

			pageReq, err := client.ReadPageRequest(cmd.Flags())
			if err != nil {
				return err
			}

			var decryptAsPrivKeyHex string
			var decryptAsPubKey string

			if argDecryptAs != "" {
				_, _, decryptAsPubKey, decryptAsPrivKeyHex, err = c.GetAddress(clientCtx, argDecryptAs)
				if err != nil {
					return err
				}
			}

			queryClient := dsvstypes.NewQueryClient(clientCtx)

			params := &dsvstypes.QueryAllAuthorizedSignatoryRequest{
				Pagination: pageReq,
			}

			res, err := queryClient.AuthorizedSignatoryAll(context.Background(), params)
			if err != nil {
				return err
			}

			// print count
			fmt.Println("Count:", len(res.AuthorizedSignatory))

			for _, authorizedSignatory := range res.AuthorizedSignatory {
				fmt.Println("Wallet ID:", authorizedSignatory.WalletID)

				if argDecryptAs != "" {
					fmt.Println("  Required Signatories:")
					for i, signatory := range authorizedSignatory.Signatory {
						var vShareSignatory types.EncryptableAuthorizedSignatory
						err = c.VShareBDecryptAndProtoUnmarshal(decryptAsPrivKeyHex, decryptAsPubKey, c.DSVSUnprotoizeVShareBindData(signatory.AuthorizedSignatoryVShareBind), signatory.EncAuthorizedSignatoryVShare, &vShareSignatory)
						fmt.Println("  ", i+1)
						if err != nil {
							fmt.Println("    Can't decrypt", c.DSVSUnprotoizeVShareBindData(signatory.AuthorizedSignatoryVShareBind).GetValidDecryptAsAddresses())
						} else {
							fmt.Println("    Signatory", c.PrettyPrint(vShareSignatory))
						}
					}
				} else {
					fmt.Println("  Required Signatories:")
					for i, signatory := range authorizedSignatory.Signatory {
						fmt.Println("  ", i+1)
						fmt.Println("    Signatory", c.PrettyPrint(signatory))
					}
				}
			}

			return nil
		},
	}

	flags.AddPaginationFlagsToCmd(cmd, cmd.Use)
	flags.AddQueryFlagsToCmd(cmd)
	cmd.Flags().StringVar(&argDecryptAs, "decrypt-as", "", "Account to decrypt as")

	return cmd
}

func CmdShowAuthorizedSignatory() *cobra.Command {
	var argVerbose bool
	var argDecryptAs string

	cmd := &cobra.Command{
		Use:   "show-authorized-signatory [wallet-id]",
		Short: "Shows an Authorized Signatory",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			clientCtx := client.GetClientContextFromCmd(cmd)

			queryClient := dsvstypes.NewQueryClient(clientCtx)

			argWalletId := args[0]

			params := &dsvstypes.QueryGetAuthorizedSignatoryRequest{
				WalletID: argWalletId,
			}

			var decryptAsPrivKeyHex string
			var decryptAsPubKey string

			if argDecryptAs != "" {
				_, _, decryptAsPubKey, decryptAsPrivKeyHex, err = c.GetAddress(clientCtx, argDecryptAs)
				if err != nil {
					return err
				}
			}

			res, err := queryClient.AuthorizedSignatory(context.Background(), params)
			if err != nil {
				return err
			}

			if argVerbose {
				err = clientCtx.PrintProto(res)
			} else {
				if argDecryptAs != "" {
					fmt.Println("Wallet ID:", res.AuthorizedSignatory.WalletID)
					for _, signatory := range res.AuthorizedSignatory.Signatory {
						var vShareAuthorizedSignatory types.EncryptableAuthorizedSignatory
						err = c.VShareBDecryptAndProtoUnmarshal(decryptAsPrivKeyHex, decryptAsPubKey, c.DSVSUnprotoizeVShareBindData(signatory.AuthorizedSignatoryVShareBind), signatory.EncAuthorizedSignatoryVShare, &vShareAuthorizedSignatory)
						if err != nil {
							fmt.Println("Can't decrypt", c.DSVSUnprotoizeVShareBindData(signatory.AuthorizedSignatoryVShareBind).GetValidDecryptAsAddresses())
							return err
						}
						fmt.Println("  ", c.PrettyPrint(vShareAuthorizedSignatory))
					}
				} else {
					fmt.Println("AuthorizedSignatory")
					fmt.Println(c.PrettyPrint(res.AuthorizedSignatory))
				}
			}

			return err
		},
	}

	flags.AddQueryFlagsToCmd(cmd)
	cmd.Flags().BoolVar(&argVerbose, "verbose", false, "Print out all info about authorized signatory")
	cmd.Flags().StringVar(&argDecryptAs, "decrypt-as", "", "Account to decrypt as")

	return cmd
}
