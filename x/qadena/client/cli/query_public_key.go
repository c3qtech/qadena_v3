package cli

import (
	"context"

	"qadena/x/qadena/types"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/spf13/cobra"
)

func CmdListPublicKey() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list-public-key",
		Short: "list all PublicKey",
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx := client.GetClientContextFromCmd(cmd)

			pageReq, err := client.ReadPageRequest(cmd.Flags())
			if err != nil {
				return err
			}

			queryClient := types.NewQueryClient(clientCtx)

			params := &types.QueryAllPublicKeyRequest{
				Pagination: pageReq,
			}

			res, err := queryClient.PublicKeyAll(context.Background(), params)
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

func CmdShowPublicKey() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "show-public-key [pub-kid]",
		Short: "shows a PublicKey",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			clientCtx := client.GetClientContextFromCmd(cmd)

			queryClient := types.NewQueryClient(clientCtx)

			argPubKID := args[0]

			params := &types.QueryGetPublicKeyRequest{
				PubKID: argPubKID,
			}

			res, err := queryClient.PublicKey(context.Background(), params)
			if err != nil {
				return err
			}

			return clientCtx.PrintProto(res)
		},
	}

	flags.AddQueryFlagsToCmd(cmd)

	return cmd
}
