package cli

import (
	"context"
	"strings"

	"github.com/c3qtech/qadena_v3/x/qadena/types"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/spf13/cobra"
)

// The parked-address queries: pioneers whose validator left the bonded set, and the address the
// staking hooks will put back when it re-bonds.
//
// Registered by hand in query.go rather than left to autocli, for the same reason as the
// scanned-contract whitelist: this module's own GetQueryCmd replaces the autocli command tree.

func CmdListParkedExternalAddress() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list-parked-external-address",
		Short: "list pioneers whose published address is parked while their validator is out of the bonded set",
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx := client.GetClientContextFromCmd(cmd)

			pageReq, err := client.ReadPageRequest(cmd.Flags())
			if err != nil {
				return err
			}

			queryClient := types.NewQueryClient(clientCtx)

			params := &types.QueryAllParkedExternalAddressRequest{
				Pagination: pageReq,
			}

			res, err := queryClient.ParkedExternalAddressAll(context.Background(), params)
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

func CmdShowParkedExternalAddress() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "show-parked-external-address [pioneer-address | valoper-address]",
		Short: "shows the address parked for one pioneer; NotFound means nothing is parked",
		Long: "Shows the address parked for one pioneer.  Takes the pioneer's account address (the row's " +
			"PubKID) or its validator operator address, which is the same key and is what " +
			"`query staking validators` prints.  NotFound means nothing is parked for it.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			clientCtx := client.GetClientContextFromCmd(cmd)

			pubKID, err := parkedPubKIDFromArg(args[0])
			if err != nil {
				return err
			}

			queryClient := types.NewQueryClient(clientCtx)

			params := &types.QueryGetParkedExternalAddressRequest{
				PubKID: pubKID,
			}

			res, err := queryClient.ParkedExternalAddress(context.Background(), params)
			if err != nil {
				return err
			}

			return clientCtx.PrintProto(res)
		},
	}

	flags.AddQueryFlagsToCmd(cmd)

	return cmd
}

// parkedPubKIDFromArg maps a validator operator address to the account address the store is keyed
// by -- the same conversion the staking hooks make.  Without it, pasting the valoper address out of
// `query staking validators` returns NotFound, which reads as "nothing parked" and is wrong.
func parkedPubKIDFromArg(arg string) (string, error) {
	if strings.HasPrefix(arg, sdk.GetConfig().GetBech32ValidatorAddrPrefix()+"1") {
		valAddr, err := sdk.ValAddressFromBech32(arg)
		if err != nil {
			return "", err
		}
		return sdk.AccAddress(valAddr).String(), nil
	}
	return arg, nil
}
