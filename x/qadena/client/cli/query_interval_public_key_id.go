package cli

import (
	"context"

	"qadena/x/qadena/types"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/spf13/cobra"

	//	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"fmt"
	"os"
	"strings"

	//	c "qadena/x/qadena/common"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func CmdListIntervalPublicKeyId() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list-interval-public-key-id",
		Short: "list all IntervalPublicKeyId",
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx := client.GetClientContextFromCmd(cmd)

			pageReq, err := client.ReadPageRequest(cmd.Flags())
			if err != nil {
				return err
			}

			queryClient := types.NewQueryClient(clientCtx)

			params := &types.QueryAllIntervalPublicKeyIDRequest{
				Pagination: pageReq,
			}

			res, err := queryClient.IntervalPublicKeyIDAll(context.Background(), params)
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

func CmdShowIntervalPublicKeyId() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "show-interval-public-key-id [node-id] [node-type]",
		Short: "shows a IntervalPublicKeyId",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			clientCtx := client.GetClientContextFromCmd(cmd)

			queryClient := types.NewQueryClient(clientCtx)

			argNodeID := args[0]
			argNodeType := args[1]

			params := &types.QueryGetIntervalPublicKeyIDRequest{
				NodeID:   argNodeID,
				NodeType: argNodeType,
			}

			res, err := queryClient.IntervalPublicKeyID(context.Background(), params)
			if err != nil {
				//				fmt.Println("err", c.PrettyPrint(err.Error()))
				st, ok := status.FromError(err)
				if ok {
					//					fmt.Println("grpcstatus code", c.PrettyPrint(st.Code()))
					//					fmt.Println("grpcstatus message", c.PrettyPrint(st.Message()))
					if st.Code() == codes.NotFound && strings.Contains(st.Message(), "not found") {
						fmt.Println("Couldn't find node type", argNodeType, " node id", argNodeID)
						os.Exit(5)
					}
				}
			}

			return clientCtx.PrintProto(res)
		},
	}

	flags.AddQueryFlagsToCmd(cmd)

	return cmd
}
