package cli

import (
	"context"

	"github.com/c3qtech/qadena_v3/x/qadena/types"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/spf13/cobra"
)

// The scanned-contract whitelist queries.
//
// Registered by hand in query.go rather than left to autocli: this module supplies its own
// GetQueryCmd, which REPLACES the autocli command tree for `query qadena`, so an autocli entry alone
// produces "unknown command" at the CLI while looking perfectly correct in the source.

func CmdListScannedContractWhitelist() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list-scanned-contract-whitelist",
		Short: "list every non-wallet party allowed to take part in a bank send",
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx := client.GetClientContextFromCmd(cmd)

			pageReq, err := client.ReadPageRequest(cmd.Flags())
			if err != nil {
				return err
			}

			queryClient := types.NewQueryClient(clientCtx)

			params := &types.QueryAllScannedContractWhitelistRequest{
				Pagination: pageReq,
			}

			res, err := queryClient.ScannedContractWhitelistAll(context.Background(), params)
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

func CmdShowScannedContractWhitelist() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "show-scanned-contract-whitelist [address]",
		Short: "shows one scanned-contract whitelist entry, with its pinned wasm code ID",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			clientCtx := client.GetClientContextFromCmd(cmd)

			queryClient := types.NewQueryClient(clientCtx)

			params := &types.QueryGetScannedContractWhitelistRequest{
				Address: args[0],
			}

			res, err := queryClient.ScannedContractWhitelist(context.Background(), params)
			if err != nil {
				return err
			}

			return clientCtx.PrintProto(res)
		},
	}

	flags.AddQueryFlagsToCmd(cmd)

	return cmd
}
