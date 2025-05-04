package cli

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/cosmos/cosmos-sdk/client"
	// "github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

var (
	DefaultRelativePacketTimeoutTimestamp = uint64((time.Duration(10) * time.Minute).Nanoseconds())
)

const (
	flagPacketTimeoutTimestamp = "packet-timeout-timestamp"
	listSeparator              = ","
)

// GetTxCmd returns the transaction commands for this module
func GetTxCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:                        types.ModuleName,
		Short:                      fmt.Sprintf("%s transactions subcommands", types.ModuleName),
		DisableFlagParsing:         true,
		SuggestionsMinimumDistance: 2,
		RunE:                       client.ValidateCmd,
	}

	cmd.AddCommand(CmdAddPublicKey())
	//	cmd.AddCommand(CmdUpdateIntervalPublicKeyId())
	//	cmd.AddCommand(CmdUpdatePioneerJar())
	//  cmd.AddCommand(CmdUpdateJarRegulator())
	cmd.AddCommand(CmdCreateWallet())
	cmd.AddCommand(CmdTransferFunds())
	cmd.AddCommand(CmdReceiveFunds())
	//		cmd.AddCommand(CmdDeploySmartContract())
	//		cmd.AddCommand(CmdExecuteSmartContract())
	cmd.AddCommand(CmdCreateCredential())
	cmd.AddCommand(CmdClaimCredential())
	//		cmd.AddCommand(CmdCreateSuspiciousTransaction())
	//		cmd.AddCommand(CmdUpdateSuspiciousTransaction())
	//		cmd.AddCommand(CmdDeleteSuspiciousTransaction())
	//		cmd.AddCommand(CmdPioneerAddPublicKey())
	//		cmd.AddCommand(CmdPioneerUpdateIntervalPublicKeyId())
	//		cmd.AddCommand(CmdPioneerEnclaveExchange())
	//		cmd.AddCommand(CmdPioneerBroadcastSecretSharePrivateKey())
	cmd.AddCommand(CmdProtectKey())
	cmd.AddCommand(CmdSignRecoverKey())
	//cmd.AddCommand(CmdCreateBulkCredentials())

	// this line is used by starport scaffolding # 1

	return cmd
}
