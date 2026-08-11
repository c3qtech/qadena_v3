package cmd

import (
	"fmt"
	"path/filepath"

	cmtcmd "github.com/cometbft/cometbft/cmd/cometbft/commands"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/spf13/cobra"

	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/cosmos/cosmos-sdk/server"
	servertypes "github.com/cosmos/cosmos-sdk/server/types"
)

// newQadenaRollbackCmd replaces the SDK's `rollback` command (registered by
// evmserver.AddCommands via sdkserver.NewRollbackCmd) with our own.
//
// WHY A REPLACEMENT EXISTS AT ALL: on this chain the application state is not a pure function of
// the blocks -- EnclaveEndBlock folds in state that lives inside the SGX enclave (see the
// invariant comment on EnclaveEndBlock in x/qadena/keeper/enclave_grpc_client.go).  Rolling back
// the chain without rolling back the enclave leaves the enclave AHEAD of the chain, and an
// enclave ahead of the chain never converges: enclaveSynchronizeStores can only SET, never
// delete.  That is not hypothetical -- the 2026-08-10 state-sync recovery attempt left Wallet,
// Credential and PublicKey OUT-OF-SYNC permanently.  This command is where the chain-side and
// enclave-side rollbacks are kept in lockstep.
//
// This version is behaviourally identical to the SDK command it shadows
// (vendor/github.com/cosmos/cosmos-sdk/server/rollback.go): one block per invocation,
// CometBFT state first, then the app store.  The enclave half and an arbitrary-height
// one-shot mode are added by later commits on this branch.
func newQadenaRollbackCmd(appCreator servertypes.AppCreator, defaultNodeHome string) *cobra.Command {
	var removeBlock bool

	cmd := &cobra.Command{
		Use:   "rollback",
		Short: "rollback Cosmos SDK and CometBFT state by one height",
		Long: `
A state rollback is performed to recover from an incorrect application state transition,
when CometBFT has persisted an incorrect app hash and is thus unable to make
progress. Rollback overwrites a state at height n with the state at height n - 1.
The application also rolls back to height n - 1. No blocks are removed, so upon
restarting CometBFT the transactions in block n will be re-executed against the
application.
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := server.GetServerContextFromCmd(cmd)
			cfg := ctx.Config
			home := cfg.RootDir
			// the SDK's unexported openDB(), replicated: the application DB lives in <home>/data
			db, err := dbm.NewDB("application", server.GetAppDBBackend(ctx.Viper), filepath.Join(home, "data"))
			if err != nil {
				return err
			}
			app := appCreator(ctx.Logger, db, nil, ctx.Viper)
			// rollback CometBFT state
			height, hash, err := cmtcmd.RollbackState(ctx.Config, removeBlock)
			if err != nil {
				return fmt.Errorf("failed to rollback CometBFT state: %w", err)
			}
			// rollback the multistore
			if err := app.CommitMultiStore().RollbackToVersion(height); err != nil {
				return fmt.Errorf("failed to rollback to version: %w", err)
			}

			fmt.Printf("Rolled back state to height %d and hash %X\n", height, hash)
			return nil
		},
	}

	cmd.Flags().String(flags.FlagHome, defaultNodeHome, "The application home directory")
	cmd.Flags().BoolVar(&removeBlock, "hard", false, "remove last block as well as state")
	return cmd
}

// replaceRollbackCmd removes the SDK-registered `rollback` command from rootCmd and installs
// ours.  Registration order matters: evmserver.AddCommands must have run first, so this is
// called immediately after it in initRootCmd.  If the SDK command is ever NOT found, that means
// the evm server stopped registering it and this shadowing is silently dead -- fail loudly
// instead of running with two commands or none.
func replaceRollbackCmd(rootCmd *cobra.Command, appCreator servertypes.AppCreator, defaultNodeHome string) {
	for _, c := range rootCmd.Commands() {
		if c.Name() == "rollback" {
			rootCmd.RemoveCommand(c)
			rootCmd.AddCommand(newQadenaRollbackCmd(appCreator, defaultNodeHome))
			return
		}
	}
	panic("qadena: expected evmserver.AddCommands to have registered a 'rollback' command to replace; it did not -- the qadena rollback command would silently not be installed")
}
