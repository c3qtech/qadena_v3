package cli

import (
	"fmt"

	wasmtypes "github.com/CosmWasm/wasmd/x/wasm/types"
	qadenatx "github.com/c3qtech/qadena_v3/x/qadena/client/tx"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/spf13/cobra"
)

func CmdExecuteWasm() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "execute-wasm [contract-address] [json-encoded-message]",
		Short: "Execute a WASM contract",
		Long: `Execute a WASM contract with the provided JSON-encoded message.
Example:
  qadenad tx qadena execute-wasm qadena14hj2tavq8fpesdwxxcu44rty3hh90vhujrvcmstl4zr3txmfvw9s0phg4d '{"release":{}}' --from alice --amount 1qdn`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Get contract address and message from arguments
			contractAddr := args[0]
			execMsg := args[1]

			// Get the client context
			ctx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}

			// Get the sender address
			sender := ctx.GetFromAddress()

			// Parse the amount flag (optional coins to send with the execution)
			amountStr, err := cmd.Flags().GetString("amount")
			if err != nil {
				return fmt.Errorf("amount: %s", err)
			}

			var amount sdk.Coins
			if amountStr != "" {
				amount, err = sdk.ParseCoinsNormalized(amountStr)
				if err != nil {
					return fmt.Errorf("invalid amount: %s", err)
				}
			}

			// Create the MsgExecuteContract message
			msg := &wasmtypes.MsgExecuteContract{
				Sender:   sender.String(),
				Contract: contractAddr,
				Msg:      []byte(execMsg),
				Funds:    amount,
			}

			// Validate the message
			if err := msg.ValidateBasic(); err != nil {
				return err
			}

			// Broadcast the transaction
			err, res := qadenatx.GenerateOrBroadcastTxCLISync(ctx, cmd.Flags(), "execute wasm contract", msg)
			if err != nil {
				fmt.Println("Error executing WASM contract:", err)
				fmt.Println("Response:", res)
				return err
			}

			fmt.Println("WASM contract executed successfully")
			return nil
		},
	}

	// Add the amount flag for optional token transfer
	cmd.Flags().String("amount", "", "Coins to send to the contract along with the execution message (e.g., 1qdn)")

	// Add standard transaction flags
	flags.AddTxFlagsToCmd(cmd)

	return cmd
}
