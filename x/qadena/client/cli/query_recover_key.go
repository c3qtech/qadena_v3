package cli

import (
	"context"

	"fmt"

	c "qadena/x/qadena/common"
	"qadena/x/qadena/types"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/hashicorp/vault/shamir"
	"github.com/spf13/cobra"
)

// this just looks at what's in the chain DB
func CmdListRecoverKey() *cobra.Command {
	var credentialID string

	cmd := &cobra.Command{
		Use:   "list-recover-key",
		Short: "list all RecoverKey",
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx := client.GetClientContextFromCmd(cmd)

			pageReq, err := client.ReadPageRequest(cmd.Flags())
			if err != nil {
				return err
			}

			queryClient := types.NewQueryClient(clientCtx)

			params := &types.QueryAllRecoverKeyRequest{
				Pagination:   pageReq,
				CredentialID: credentialID,
			}

			res, err := queryClient.RecoverKeyAll(context.Background(), params)
			if err != nil {
				return err
			}

			return clientCtx.PrintProto(res)
		},
	}

	flags.AddPaginationFlagsToCmd(cmd, cmd.Use)
	flags.AddQueryFlagsToCmd(cmd)
	cmd.Flags().StringVar(&credentialID, "credential-id", "", "")

	return cmd
}

// this actually goes into the enclave
func CmdShowRecoverKey() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "show-recover-key [recover-wallet-id]",
		Short: "shows a RecoverKey",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			clientCtx := client.GetClientContextFromCmd(cmd)

			queryClient := types.NewQueryClient(clientCtx)

			argWalletID, _, _, _, err := c.GetAddress(clientCtx, args[0])
			if err != nil {
				return err
			}

			params := &types.QueryGetRecoverKeyRequest{
				WalletID: argWalletID,
			}

			res, err := queryClient.RecoverKey(context.Background(), params)
			if err != nil {
				return err
			}

			recoverKey := res.GetRecoverKey()

			fmt.Println("recoverKey", c.PrettyPrint(recoverKey))

			_, _, credPubKey, credPrivKeyHex, err := c.GetAddress(clientCtx, args[0]+"-credential")
			if err != nil {
				return err
			}
			credPrivateKey := credPrivKeyHex + "_privkhex:" + credPubKey + "_privk"

			if len(recoverKey.RecoverShare) == 1 {
				var seedPhrase string
				_, err := c.BDecryptAndUnmarshal(credPrivateKey, recoverKey.RecoverShare[0].EncWalletPubKShare, &seedPhrase)
				if err != nil {
					fmt.Println("couldn't decrypt " + err.Error())
					return err
				}
				fmt.Println("seed phrase", seedPhrase)
			} else {
				// assemble!
				var byteShares [][]byte
				var shareString string
				for _, rShare := range recoverKey.RecoverShare {
					_, err := c.BDecryptAndUnmarshal(credPrivateKey, rShare.EncWalletPubKShare, &shareString)
					if err != nil {
						fmt.Println("couldn't decrypt " + err.Error())
						return err
					}
					byteShares = append(byteShares, []byte(shareString))
				}
				seedPhrase, err := shamir.Combine(byteShares)
				if err != nil {
					fmt.Println("error from shamir", err.Error())
					return err
				}
				fmt.Println("seed phrase:", string(seedPhrase))
			}

			return nil
		},
	}

	flags.AddQueryFlagsToCmd(cmd)

	return cmd
}
