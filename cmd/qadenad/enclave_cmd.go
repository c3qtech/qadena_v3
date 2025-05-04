package main

import (
	"context"
	"fmt"
	"os"
	"time"

	c "qadena/x/qadena/common"
	"qadena/x/qadena/types"

	"cosmossdk.io/log"
	"github.com/cosmos/cosmos-sdk/client"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	logger                     log.Logger
	debug                      = true
	verbose                    = false
	SupportsUnixDomainSockets  = true
	DefaultPort                = 50051
	addr, signerArg, uniqueArg string
)

const (
	ArmorPassPhrase = "8675309" // this is only used in-process, in the enclave, does not affect security
)

func NewEnclaveCmd() *cobra.Command {
	logger = c.NewTMLogger("enclave_cmd")

	cmd := &cobra.Command{
		Use:   "enclave",
		Short: "Manage the enclave",
		Long: `Manage the enclave with various subcommands:
check-enclave   - Check the enclave status		
init-enclave    - Initialize enclave for use by the genesis node
sync-enclave    - Sync enclave for use by new full/validator nodes
export-private-key - Export private key (for demo purposes)
remove-private-key - Remove private key from cache (for debug)
export-private-state - Export enclave state (for debug)
update-ss-interval-key - Update SS interval key`,
	}

	cmd.PersistentFlags().String("addr", "localhost:50051", "the address to connect to")
	cmd.PersistentFlags().String("enclave-signer-id", "", "Enclave signer ID")
	cmd.PersistentFlags().String("enclave-unique-id", "", "Enclave unique ID")

	cmd.AddCommand(
		newCheckEnclaveCmd(),
		newInitEnclaveCmd(),
		newSyncEnclaveCmd(),
		newExportPrivateKeyCmd(),
		newRemovePrivateKeyCmd(),
		newExportPrivateStateCmd(),
		newUpdateSSIntervalKeyCmd(),
	)

	return cmd
}

func newCheckEnclaveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "check-enclave",
		Short: "Check the enclave status",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := getEnclaveConnection(cmd)
			if err != nil {
				c.LoggerError(logger, "Enclave is not running", err)
				os.Exit(10)
				return err
			}

			c.LoggerInfo(logger, "Enclave is running")
			os.Exit(0)
			return nil
		},
	}
}

func newSyncEnclaveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "sync-enclave [PioneerID] [Advertise-IP-Address] [SeedNodeURI]",
		Short: "Sync enclave for use by new full/validator nodes",
		Args:  cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			enclaveClient, err := getEnclaveConnection(cmd)
			if err != nil {
				return err
			}

			ctx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}

			_, _, _, _, armorPrivK, err := c.GetAddressByName(ctx, args[0], ArmorPassPhrase)
			if err != nil {
				return err
			}

			e := types.MsgSyncEnclave{
				PioneerID:              args[0],
				ExternalAddress:        args[1],
				PioneerArmorPrivK:      armorPrivK,
				PioneerArmorPassPhrase: ArmorPassPhrase,
				SeedNode:               args[2],
			}
			grpcctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			r2, err := enclaveClient.SyncEnclave(grpcctx, &e)
			if err != nil {
				c.LoggerError(logger, "could not sync enclave", err)
				return err
			}
			c.LoggerDebug(logger, "SyncEnclave returns", r2)
			if r2.Status {
				c.LoggerInfo(logger, "SyncEnclave SUCCEEDED")
				return nil
			}

			return fmt.Errorf("init enclave failed")
		},
	}
}

func newInitEnclaveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init-enclave [PioneerID] [Advertise-IP-Address] [JarID] [RegulatorID]",
		Short: "Initialize enclave for use by the genesis node",
		Args:  cobra.ExactArgs(4),
		RunE: func(cmd *cobra.Command, args []string) error {
			enclaveClient, err := getEnclaveConnection(cmd)
			if err != nil {
				return err
			}
			signerID, _ := cmd.Flags().GetString("enclave-signer-id")
			uniqueID, _ := cmd.Flags().GetString("enclave-unique-id")

			ctx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}

			_, _, _, _, armorPrivK, err := c.GetAddressByName(ctx, args[0], ArmorPassPhrase)
			if err != nil {
				return err
			}

			e := types.MsgInitEnclave{
				PioneerID:              args[0],
				ExternalAddress:        args[1],
				JarID:                  args[2],
				RegulatorID:            args[3],
				PioneerArmorPrivK:      armorPrivK,
				PioneerArmorPassPhrase: ArmorPassPhrase,
				SignerID:               signerID,
				UniqueID:               uniqueID,
			}

			grpcctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			r2, err := enclaveClient.InitEnclave(grpcctx, &e)
			if err != nil {
				c.LoggerError(logger, "could not init enclave", err)
				return err
			}
			if debug && verbose {
				c.LoggerDebug(logger, "InitEnclave returns", r2)
			}
			if r2.Status {
				return nil
			}
			return fmt.Errorf("init enclave failed")
		},
	}
}

func newExportPrivateKeyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "export-private-key [pubKID]",
		Short: "Export private key for a given pubKID",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			enclaveClient, err := getEnclaveConnection(cmd)
			if err != nil {
				return err
			}

			grpcctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			r2, err := enclaveClient.ExportPrivateKey(grpcctx, &types.MsgExportPrivateKey{
				PubKID: args[0],
			})
			if err != nil {
				c.LoggerError(logger, "could not export private key", err)
				return err
			}
			if debug && verbose {
				c.LoggerDebug(logger, "ExportPrivateKey returns", r2)
			}

			return nil
		},
	}
}

func newRemovePrivateKeyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "remove-private-key [pubKID]",
		Short: "Remove private key for a given pubKID",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			enclaveClient, err := getEnclaveConnection(cmd)
			if err != nil {
				return err
			}

			grpcctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			r2, err := enclaveClient.RemovePrivateKey(grpcctx, &types.MsgRemovePrivateKey{
				PubKID: args[0],
			})
			if err != nil {
				c.LoggerError(logger, "could not remove private key", err)
				return err
			}
			if debug && verbose {
				c.LoggerDebug(logger, "RemovePrivateKey returns", r2)
			}

			return nil
		},
	}
}

func newExportPrivateStateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "export-private-state [pubKID]",
		Short: "Export private state for a given pubKID",
		Args:  cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			enclaveClient, err := getEnclaveConnection(cmd)
			if err != nil {
				return err
			}

			grpcctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			r2, err := enclaveClient.ExportPrivateState(grpcctx, &types.MsgExportPrivateState{})
			if err != nil {
				c.LoggerError(logger, "could not export private state", err)
				return err
			}
			if debug && verbose {
				c.LoggerDebug(logger, "ExportPrivateState returns", r2)
			}

			return nil
		},
	}
}

func newUpdateSSIntervalKeyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "update-ss-interval-key",
		Short: "Update the interval key for the private state",
		Args:  cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			enclaveClient, err := getEnclaveConnection(cmd)
			if err != nil {
				return err
			}

			grpcctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			r2, err := enclaveClient.UpdateSSIntervalKey(grpcctx, &types.MsgUpdateSSIntervalKey{})
			if err != nil {
				c.LoggerError(logger, "could not update the interval key for the private state", err)
				return err
			}
			if debug && verbose {
				c.LoggerDebug(logger, "UpdateSSIntervalKey returns", r2)
			}

			return nil
		},
	}
}

// Helper function to get gRPC connection
func getEnclaveConnection(cmd *cobra.Command) (types.QadenaEnclaveClient, error) {
	var conn *grpc.ClientConn
	var err error

	if SupportsUnixDomainSockets {
		addr = fmt.Sprintf("unix:///tmp/qadena_%d.sock", DefaultPort)

		if debug {
			c.LoggerDebug(logger, "Will connect to QadenaDEnclave (unix domain socket)", addr)
		}
		conn, err = grpc.Dial(addr, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithTimeout(time.Duration(5)*time.Second))
	} else {
		c.LoggerError(logger, "Not supported", err)
		return nil, fmt.Errorf("not supported")
	}

	if err != nil {
		c.LoggerError(logger, "Did not connect", err)
		return nil, err
	}

	greeterClient := types.NewGreeterClient(conn)

	// Contact the server and print out its response.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	r, err := greeterClient.SayHello(ctx, &types.HelloRequest{Name: "Pong"})
	if err != nil {
		c.LoggerError(logger, "Could not greet", err)
		return nil, err
	}
	if debug {
		c.LoggerDebug(logger, "Greeting", r.GetMessage())
	}

	enclaveClient := types.NewQadenaEnclaveClient(conn)

	return enclaveClient, nil
}
