package cli

import (
	"context"

	"qadena_v3/x/qadena/types"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/spf13/cobra"
)

func CmdListEnclaveIdentity() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list-enclave-identity",
		Short: "list all EnclaveIdentity",
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx := client.GetClientContextFromCmd(cmd)

			pageReq, err := client.ReadPageRequest(cmd.Flags())
			if err != nil {
				return err
			}

			queryClient := types.NewQueryClient(clientCtx)

			params := &types.QueryAllEnclaveIdentityRequest{
				Pagination: pageReq,
			}

			res, err := queryClient.EnclaveIdentityAll(context.Background(), params)
			if err != nil {
				return err
			}

			return clientCtx.PrintProto(res)
		},
	}

	flags.AddPaginationFlagsToCmd(cmd, cmd.Use)
	flags.AddQueryFlagsToCmd(cmd)

	return cmd
}

func CmdShowEnclaveIdentity() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "show-enclave-identity [enclave-unique-id]",
		Short: "shows a EnclaveIdentity",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			clientCtx := client.GetClientContextFromCmd(cmd)

			queryClient := types.NewQueryClient(clientCtx)

			argEnclaveIdentityUniqueID := args[0]

			params := &types.QueryGetEnclaveIdentityRequest{
				UniqueID: argEnclaveIdentityUniqueID,
			}

			res, err := queryClient.EnclaveIdentity(context.Background(), params)
			if err != nil {
				return err
			}

			return clientCtx.PrintProto(res)
		},
	}

	flags.AddQueryFlagsToCmd(cmd)

	return cmd
}
