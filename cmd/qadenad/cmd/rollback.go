package cmd

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	cmtdbm "github.com/cometbft/cometbft-db"
	cmtcmd "github.com/cometbft/cometbft/cmd/cometbft/commands"
	cmtcfg "github.com/cometbft/cometbft/config"
	cmtstate "github.com/cometbft/cometbft/state"
	cmtstore "github.com/cometbft/cometbft/store"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/spf13/cobra"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/cosmos/cosmos-sdk/server"
	servertypes "github.com/cosmos/cosmos-sdk/server/types"

	"github.com/c3qtech/qadena_v3/x/qadena/keeper"
	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

// newQadenaRollbackCmd replaces the SDK's `rollback` command (registered by
// evmserver.AddCommands via sdkserver.NewRollbackCmd) with one that rolls the CHAIN AND THE
// ENCLAVE together, and that can rewind to an arbitrary height in one invocation.
//
// WHY A REPLACEMENT EXISTS AT ALL: on this chain the application state is not a pure function of
// the blocks -- EnclaveEndBlock folds in state that lives inside the SGX enclave (see the
// invariant comment on EnclaveEndBlock in x/qadena/keeper/enclave_grpc_client.go).  Rolling back
// the chain without rolling back the enclave leaves the enclave AHEAD of the chain, and an
// enclave ahead of the chain never converges: enclaveSynchronizeStores can only SET, never
// delete.  That is not hypothetical -- the 2026-08-10 state-sync recovery attempt left Wallet,
// Credential and PublicKey OUT-OF-SYNC permanently.
//
// WHY --height EXISTS: the stock one-block command cannot be looped at scale.  Measured on the
// 2026-08-10 incident: 4.4s per invocation degrading to 20.7s (goleveldb tombstones accumulating
// across process restarts), extrapolating to ~33 days for the 31,675-block rewind.  One-shot,
// the CometBFT half loops in-process against open stores (block-meta shifts, no app involvement)
// and the app store half is a single RollbackToVersion: one range deletion instead of 31,675.
//
// ORDER: enclave preflight (refuse doomed targets before touching anything), then chain, then
// enclave.  Chain-first matters: if the enclave call then fails, the chain is BEHIND the enclave,
// which startup reconciliation repairs automatically.  The reverse order can leave the enclave
// behind the chain -- the one direction nothing can repair in place.
func newQadenaRollbackCmd(appCreator servertypes.AppCreator, defaultNodeHome string) *cobra.Command {
	var removeBlock bool
	var targetHeight int64

	cmd := &cobra.Command{
		Use:   "rollback",
		Short: "rollback Cosmos SDK, CometBFT and enclave state by one height (or to --height)",
		Long: `
A state rollback is performed to recover from an incorrect application state transition.
Rollback overwrites a state at height n with the state at height n - 1, rolls the
application store back to match, and rolls the qadena enclave's store back in lockstep --
a chain-only rollback would leave the enclave ahead of the chain, which never converges.

With --height H, rewinds all three to height H in one invocation (implies removing the
blocks above H, as --hard does).  Without it, rolls back exactly one height; the
transactions in block n are re-executed against the application on restart unless --hard
also removed the block.

qadenad itself must be stopped.  The enclave need not be: if none is serving, this command
spawns one for the duration and stops it before returning; one already running (started
externally) is used and left running.
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
			// SELF-CONTAINED: if no enclave is serving, app construction below spawns one, and
			// the deferred stop takes it down again on every exit path -- so the operator runs
			// ONE command with the node stopped, nothing else.  An enclave that is already
			// running (started externally, e.g. under a debugger) is adopted instead, and the
			// deferred stop leaves it alone: StopSpawnedEnclaves only stops what THIS process
			// spawned.  No signer is needed for a rollback.
			keeper.EnableEnclaveSpawn(keeper.SpawnModeRollback)
			defer keeper.StopSpawnedEnclaves()
			// constructing the app dials the enclave and panics if it is unreachable
			// (app.New -> QadenaKeeper.InitEnclave), so from here on the enclave is known live
			app := appCreator(ctx.Logger, db, nil, ctx.Viper)

			// ---- enclave preflight: refuse doomed targets before touching anything ----
			enclaveHeights, err := enclaveGetHeight()
			if err != nil {
				if status.Code(err) == codes.Unimplemented {
					return fmt.Errorf("the running enclave predates height bookkeeping and cannot be rolled back; a chain-only rollback would create an enclave-ahead divergence that never converges -- upgrade qadenad_enclave first")
				}
				return fmt.Errorf("cannot read the enclave's height watermarks: %w", err)
			}

			if targetHeight != 0 {
				// ---- one-shot mode ----
				if targetHeight < 1 {
					return fmt.Errorf("invalid --height %d", targetHeight)
				}
				if enclaveHeights.PreparedHeight < targetHeight {
					return fmt.Errorf("the enclave is at height %d, below the requested %d: rolling the chain there would leave the enclave BEHIND, which nothing can repair in place -- the highest safe target is %d", enclaveHeights.PreparedHeight, targetHeight, enclaveHeights.PreparedHeight)
				}
				if enclaveHeights.EarliestHeight == 0 || targetHeight < enclaveHeights.EarliestHeight {
					return fmt.Errorf("height %d is below the enclave's rollback horizon (%d): the enclave cannot follow the chain there", targetHeight, enclaveHeights.EarliestHeight)
				}

				// chain first: CometBFT loops in-process against open stores...
				reached, err := rollbackCometToHeight(cfg, targetHeight)
				if err != nil {
					return fmt.Errorf("failed to rollback CometBFT state: %w", err)
				}
				if reached != targetHeight {
					return fmt.Errorf("CometBFT rollback stopped at height %d, wanted %d", reached, targetHeight)
				}
				// ...then ONE app-store rollback: a single range deletion, not one per block
				if err := app.CommitMultiStore().RollbackToVersion(targetHeight); err != nil {
					return fmt.Errorf("failed to rollback app store to version %d: %w", targetHeight, err)
				}
				// ...then the enclave, in lockstep
				if err := enclaveRollback(targetHeight); err != nil {
					return fmt.Errorf("chain is now at height %d but the ENCLAVE ROLLBACK FAILED: %w", targetHeight, err)
				}
				fmt.Printf("Rolled back chain and enclave to height %d\n", targetHeight)
				return nil
			}

			// ---- stock one-block mode, plus the enclave ----
			// The landing height is (current - 1); refuse before touching the chain if the
			// enclave cannot follow there.  The app store's latest version is the chain height
			// (the comet stores cannot be opened here -- RollbackState takes its own leveldb
			// locks), so this preflight is approximate by at most one in the crash windows;
			// enclaveRollback below re-checks exactly.
			landing := app.CommitMultiStore().LatestVersion() - 1
			if enclaveHeights.PreparedHeight < landing {
				return fmt.Errorf("the enclave is at height %d, below the landing height %d: rolling the chain back would leave the enclave BEHIND, which nothing can repair in place -- roll back with --height %d instead", enclaveHeights.PreparedHeight, landing, enclaveHeights.PreparedHeight)
			}
			height, hash, err := cmtcmd.RollbackState(ctx.Config, removeBlock)
			if err != nil {
				return fmt.Errorf("failed to rollback CometBFT state: %w", err)
			}
			if err := app.CommitMultiStore().RollbackToVersion(height); err != nil {
				return fmt.Errorf("failed to rollback to version: %w", err)
			}
			if err := enclaveRollback(height); err != nil {
				return fmt.Errorf("chain is now at height %d but the ENCLAVE ROLLBACK FAILED: %w", height, err)
			}

			fmt.Printf("Rolled back chain and enclave to height %d and hash %X\n", height, hash)
			return nil
		},
	}

	cmd.Flags().String(flags.FlagHome, defaultNodeHome, "The application home directory")
	cmd.Flags().BoolVar(&removeBlock, "hard", false, "remove last block as well as state")
	cmd.Flags().Int64Var(&targetHeight, "height", 0, "rewind chain, app store and enclave to this height in one invocation (implies --hard for the removed range)")
	return cmd
}

// rollbackCometToHeight loops the one-block CometBFT rollback in-process, with the block and
// state stores opened ONCE.  Each step is cheap -- block-meta shifts and a state rebuild from the
// adjacent block, no app involvement -- which is what makes an arbitrary-depth rewind practical.
// Blocks above the target are removed (state.Rollback with removeBlock=true): in a fork recovery
// they are the discarded fork, and leaving them would make CometBFT replay them on restart.
//
// Store construction mirrors cometbft's own unexported loadStateAndBlockStore
// (vendor/github.com/cometbft/cometbft/cmd/cometbft/commands/rollback.go).
func rollbackCometToHeight(cfg *cmtcfg.Config, targetHeight int64) (int64, error) {
	dbType := cmtdbm.BackendType(cfg.DBBackend)

	blockStoreDB, err := cmtdbm.NewDB("blockstore", dbType, cfg.DBDir())
	if err != nil {
		return 0, err
	}
	blockStore := cmtstore.NewBlockStore(blockStoreDB)
	defer blockStore.Close()

	stateDB, err := cmtdbm.NewDB("state", dbType, cfg.DBDir())
	if err != nil {
		return 0, err
	}
	stateStore := cmtstate.NewStore(stateDB, cmtstate.StoreOptions{
		DiscardABCIResponses: cfg.Storage.DiscardABCIResponses,
	})
	defer stateStore.Close()

	if blockStore.Height() <= targetHeight {
		return 0, fmt.Errorf("blockstore is at height %d, not above the target %d", blockStore.Height(), targetHeight)
	}
	if base := blockStore.Base(); targetHeight < base {
		return 0, fmt.Errorf("target height %d is below the blockstore's base %d (pruned)", targetHeight, base)
	}

	var height int64
	start := time.Now()
	for {
		height, _, err = cmtstate.Rollback(blockStore, stateStore, true)
		if err != nil {
			return height, err
		}
		if height <= targetHeight {
			break
		}
		// a deep rewind is silent for minutes otherwise
		if n := blockStore.Height() - targetHeight; n%5000 == 0 {
			fmt.Printf("  ...%d blocks to go (%s elapsed)\n", n, time.Since(start).Round(time.Second))
		}
	}
	return height, nil
}

// enclaveGetHeight reads the enclave's watermarks over the connection app construction opened.
func enclaveGetHeight() (*types.GetEnclaveHeightReply, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return keeper.EnclaveGRPCClient.GetEnclaveHeight(ctx, &types.MsgGetEnclaveHeight{})
}

// enclaveRollback rolls the enclave to the height the chain now sits at.  "Already at that
// height" counts as success -- the command must be safe to re-run.  On failure it re-reads the
// watermarks so the error names the actual direction of the divergence, because the two
// directions have opposite remedies (enclave ahead: re-run or let startup reconciliation fix it;
// enclave behind: the chain must roll back further).
func enclaveRollback(height int64) error {
	// a deep rollback rebuilds the IAVL fast-node index; give it real time
	ctx, cancel := context.WithTimeout(context.Background(), keeper.EnclaveRollbackTimeout)
	defer cancel()
	r, err := keeper.EnclaveGRPCClient.RollbackToHeight(ctx, &types.MsgRollbackToHeight{Height: height})
	if err != nil {
		if h, herr := enclaveGetHeight(); herr == nil {
			switch {
			case h.PreparedHeight < height:
				return fmt.Errorf("%w\nthe enclave is at height %d, BEHIND the chain's %d -- nothing repairs this in place; roll the chain back further: qadenad rollback --height %d", err, h.PreparedHeight, height, h.PreparedHeight)
			case h.PreparedHeight > height:
				return fmt.Errorf("%w\nthe enclave is at height %d, ahead of the chain's %d -- startup reconciliation repairs this automatically, or re-run this command", err, h.PreparedHeight, height)
			}
		}
		return err
	}
	if !r.RolledBack {
		fmt.Printf("enclave: %s\n", r.Reason)
	} else {
		fmt.Printf("enclave: rolled back from height %d (version %d) to height %d (version %d)\n", r.FromHeight, r.FromVersion, r.ToHeight, r.ToVersion)
	}
	return nil
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
