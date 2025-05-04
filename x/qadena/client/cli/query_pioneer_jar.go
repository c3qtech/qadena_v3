package cli

import (
	"context"

	"qadena_v3/x/qadena/types"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/spf13/cobra"
)

func CmdListPioneerJar() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list-pioneer-jar",
		Short: "list all PioneerJar",
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx := client.GetClientContextFromCmd(cmd)

			pageReq, err := client.ReadPageRequest(cmd.Flags())
			if err != nil {
				return err
			}

			queryClient := types.NewQueryClient(clientCtx)

			params := &types.QueryAllPioneerJarRequest{
				Pagination: pageReq,
			}

			res, err := queryClient.PioneerJarAll(context.Background(), params)
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

func CmdShowPioneerJar() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "show-pioneer-jar [pioneer-id]",
		Short: "shows a PioneerJar",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			clientCtx := client.GetClientContextFromCmd(cmd)

			queryClient := types.NewQueryClient(clientCtx)

			argPioneerID := args[0]

			params := &types.QueryGetPioneerJarRequest{
				PioneerID: argPioneerID,
			}

			res, err := queryClient.PioneerJar(context.Background(), params)
			if err != nil {
				return err
			}

			return clientCtx.PrintProto(res)
		},
	}

	flags.AddQueryFlagsToCmd(cmd)

	return cmd
}
