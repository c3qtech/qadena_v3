package cli

import (
	"context"

	"github.com/c3qtech/qadena_v3/x/qadena/types"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/spf13/cobra"
)

// CmdEnclaveMeasurement asks a node which enclave build it runs.
//
// REGISTERED HERE, not in autocli.go.  This module supplies its own GetQueryCmd, which replaces the
// autocli command tree -- an entry added only to autocli.go compiles, reads correctly, and then
// reports `unknown command` at the CLI.  That is exactly what happened to this query: the pre-check
// in add_full_node.sh could never ask, said so, and carried on to wipe the node it was meant to
// protect.  The note in autocli.go says as much; it had to be discovered anyway.
//
// Unauthenticated on purpose: a measurement is not a secret -- genesis records it and the chain
// publishes it as an EnclaveIdentity -- and the caller needs it BEFORE it can attest anything.
func CmdEnclaveMeasurement() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "enclave-measurement",
		Short: "Show which enclave build this node runs, and whether it can bootstrap a joiner",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx := client.GetClientContextFromCmd(cmd)

			queryClient := types.NewQueryClient(clientCtx)

			res, err := queryClient.EnclaveMeasurement(context.Background(), &types.QueryEnclaveMeasurementRequest{})
			if err != nil {
				return err
			}

			return clientCtx.PrintProto(res)
		},
	}

	flags.AddQueryFlagsToCmd(cmd)

	return cmd
}
