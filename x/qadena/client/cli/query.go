package cli

import (
	"fmt"
	// "strings"

	"github.com/spf13/cobra"

	"github.com/cosmos/cosmos-sdk/client"
	// "github.com/cosmos/cosmos-sdk/client/flags"
	// sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

// GetQueryCmd returns the cli query commands for this module
func GetQueryCmd() *cobra.Command {
	// Group qadena queries under a subcommand
	cmd := &cobra.Command{
		Use:                        types.ModuleName,
		Short:                      fmt.Sprintf("Querying commands for the %s module", types.ModuleName),
		DisableFlagParsing:         true,
		SuggestionsMinimumDistance: 2,
		RunE:                       client.ValidateCmd,
	}

	cmd.AddCommand(CmdListCredential())
	cmd.AddCommand(CmdShowCredential())
	cmd.AddCommand(CmdListWallet())
	cmd.AddCommand(CmdShowWallet())
	cmd.AddCommand(CmdFindCredential())
	cmd.AddCommand(CmdShowIntervalPublicKeyId())
	cmd.AddCommand(CmdShowRecoverKey())
	cmd.AddCommand(CmdListSuspiciousTransaction())
	cmd.AddCommand(CmdShowSuspiciousTransaction())

	cmd.AddCommand(CmdListIntervalPublicKeyId())
	cmd.AddCommand(CmdQueryParams())
	cmd.AddCommand(CmdListPublicKey())
	cmd.AddCommand(CmdShowPublicKey())
	cmd.AddCommand(CmdListPioneerJar())
	cmd.AddCommand(CmdShowPioneerJar())
	cmd.AddCommand(CmdListJarRegulator())
	cmd.AddCommand(CmdShowJarRegulator())

	cmd.AddCommand(CmdTreasury())

	cmd.AddCommand(CmdConvertToCompressedPC())

	//	cmd.AddCommand(CmdAccount())

	cmd.AddCommand(CmdIncentives())

	//	cmd.AddCommand(CmdSyncEnclave())

	//	cmd.AddCommand(CmdEnclaveSecretShare())

	cmd.AddCommand(CmdListProtectKey())
	cmd.AddCommand(CmdShowProtectKey())

	cmd.AddCommand(CmdListEnclaveIdentity())
	cmd.AddCommand(CmdShowEnclaveIdentity())
	//	cmd.AddCommand(CmdEnclaveRecoverKeyShare())

	// this line is used by starport scaffolding # 1

	//	cmd.AddCommand(CmdExportPrivateKey())

	return cmd
}
