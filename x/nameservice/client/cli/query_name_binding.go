package cli

import (
	"context"

	"qadena_v3/x/nameservice/types"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/spf13/cobra"

	"fmt"
)

func CmdListNameBinding() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list-name-binding",
		Short: "list all NameBinding",
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx := client.GetClientContextFromCmd(cmd)

			pageReq, err := client.ReadPageRequest(cmd.Flags())
			if err != nil {
				return err
			}

			queryClient := types.NewQueryClient(clientCtx)

			params := &types.QueryAllNameBindingRequest{
				Pagination: pageReq,
			}

			res, err := queryClient.NameBindingAll(context.Background(), params)
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

func CmdShowNameBinding() *cobra.Command {
	var argVerbose bool
	cmd := &cobra.Command{
		Use:   "show-name-binding [credential] [credential-type]",
		Short: "shows a NameBinding",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			clientCtx := client.GetClientContextFromCmd(cmd)

			queryClient := types.NewQueryClient(clientCtx)

			argCredential := args[0]
			argCredentialType := args[1]

			params := &types.QueryGetNameBindingRequest{
				Credential:     argCredential,
				CredentialType: argCredentialType,
			}

			res, err := queryClient.NameBinding(context.Background(), params)
			if err != nil {
				return err
			}

			if argVerbose {
				err = clientCtx.PrintProto(res)
			} else {
				fmt.Println(res.NameBinding.Address)
			}

			return err
		},
	}

	flags.AddQueryFlagsToCmd(cmd)
	cmd.Flags().BoolVar(&argVerbose, "verbose", false, "Print out all info about binding")

	return cmd
}
