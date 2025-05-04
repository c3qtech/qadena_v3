package cli

import (
	"context"

	"github.com/c3qtech/qadena_v3/x/qadena/types"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/spf13/cobra"
)

func CmdListJarRegulator() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list-jar-regulator",
		Short: "list all JarRegulator",
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx := client.GetClientContextFromCmd(cmd)

			pageReq, err := client.ReadPageRequest(cmd.Flags())
			if err != nil {
				return err
			}

			queryClient := types.NewQueryClient(clientCtx)

			params := &types.QueryAllJarRegulatorRequest{
				Pagination: pageReq,
			}

			res, err := queryClient.JarRegulatorAll(context.Background(), params)
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

func CmdShowJarRegulator() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "show-jar-regulator [jar-id]",
		Short: "shows a JarRegulator",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			clientCtx := client.GetClientContextFromCmd(cmd)

			queryClient := types.NewQueryClient(clientCtx)

			argJarID := args[0]

			params := &types.QueryGetJarRegulatorRequest{
				JarID: argJarID,
			}

			res, err := queryClient.JarRegulator(context.Background(), params)
			if err != nil {
				return err
			}

			return clientCtx.PrintProto(res)
		},
	}

	flags.AddQueryFlagsToCmd(cmd)

	return cmd
}
