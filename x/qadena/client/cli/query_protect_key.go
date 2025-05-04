package cli

import (
	"context"

	"github.com/c3qtech/qadena_v3/x/qadena/types"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/spf13/cobra"
)

func CmdListProtectKey() *cobra.Command {
	var credentialID string

	cmd := &cobra.Command{
		Use:   "list-protect-key",
		Short: "list all ProtectKey",
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx := client.GetClientContextFromCmd(cmd)

			pageReq, err := client.ReadPageRequest(cmd.Flags())
			if err != nil {
				return err
			}

			queryClient := types.NewQueryClient(clientCtx)

			params := &types.QueryAllProtectKeyRequest{
				Pagination:   pageReq,
				CredentialID: credentialID,
			}

			res, err := queryClient.ProtectKeyAll(context.Background(), params)
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

func CmdShowProtectKey() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "show-protect-key [wallet-id]",
		Short: "shows a ProtectKey",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			clientCtx := client.GetClientContextFromCmd(cmd)

			queryClient := types.NewQueryClient(clientCtx)

			argWalletID := args[0]

			params := &types.QueryGetProtectKeyRequest{
				WalletID: argWalletID,
			}

			res, err := queryClient.ProtectKey(context.Background(), params)
			if err != nil {
				return err
			}

			return clientCtx.PrintProto(res)
		},
	}

	flags.AddQueryFlagsToCmd(cmd)

	return cmd
}
