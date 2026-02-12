package cmd

import (
	"errors"
	"io"
	"path/filepath"
	"strings"

	"cosmossdk.io/log"
	confixcmd "cosmossdk.io/tools/confix/cmd"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/cosmos/cosmos-sdk/client"

	//	"github.com/cosmos/cosmos-sdk/version"

	//	"github.com/cosmos/cosmos-sdk/client/debug"
	"github.com/cosmos/cosmos-sdk/client/flags"
	//	"github.com/cosmos/cosmos-sdk/client/keys"
	"github.com/cosmos/cosmos-sdk/client/pruning"
	"github.com/cosmos/cosmos-sdk/client/rpc"
	"github.com/cosmos/cosmos-sdk/client/snapshot"
	"github.com/cosmos/cosmos-sdk/server"
	servertypes "github.com/cosmos/cosmos-sdk/server/types"
	"github.com/cosmos/cosmos-sdk/types/module"
	authcmd "github.com/cosmos/cosmos-sdk/x/auth/client/cli"
	"github.com/cosmos/cosmos-sdk/x/crisis"
	genutilcli "github.com/cosmos/cosmos-sdk/x/genutil/client/cli"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	wasmkeeper "github.com/CosmWasm/wasmd/x/wasm/keeper"
	"github.com/c3qtech/qadena_v3/app"
	c "github.com/c3qtech/qadena_v3/x/qadena/common"

	evmcosmoscmd "github.com/cosmos/evm/client"
	evmdebug "github.com/cosmos/evm/client/debug"

	evmserver "github.com/cosmos/evm/server"
	evmsrvflags "github.com/cosmos/evm/server/flags"
	evmtypes "github.com/cosmos/evm/x/vm/types"

	genutiltypes "github.com/cosmos/cosmos-sdk/x/genutil/types"
	"github.com/spf13/cast"
	// cmtcmd "github.com/cometbft/cometbft/cmd/cometbft/commands"
	// sdkserver "github.com/cosmos/cosmos-sdk/server"
	// "github.com/cosmos/cosmos-sdk/server/types"
)

func initRootCmd(
	rootCmd *cobra.Command,
	txConfig client.TxConfig,
	basicManager module.BasicManager,
) {
	sdkAppCreator := func(l log.Logger, d dbm.DB, w io.Writer, ao servertypes.AppOptions) servertypes.Application {
		return newApp(l, d, w, ao)
	}

	rootCmd.AddCommand(
		genutilcli.InitCmd(basicManager, app.DefaultNodeHome),
		evmdebug.Cmd(), // EVM
		//		debug.Cmd(), -- replaced by above
		confixcmd.ConfigCommand(),
		pruning.Cmd(sdkAppCreator, app.DefaultNodeHome),
		snapshot.Cmd(sdkAppCreator),
	)

	//	evmAddCommands(rootCmd, app.DefaultNodeHome, newApp, appExport, addModuleInitFlags)

	// add Cosmos EVM' flavored TM commands to start server, etc.
	evmserver.AddCommands(
		rootCmd,
		evmserver.NewDefaultStartOptions(newApp, app.DefaultNodeHome),
		appExport,
		addModuleInitFlags,
	)

	// add Cosmos EVM key commands
	rootCmd.AddCommand(
		evmcosmoscmd.KeyCommands(app.DefaultNodeHome, true),
	)

	// add keybase, auxiliary RPC, query, genesis, and tx child commands
	rootCmd.AddCommand(
		server.StatusCommand(),
		genesisCommand(txConfig, basicManager),
		queryCommand(),
		txCommand(),
		//		keys.Commands(), // replaced by evm version
	)

	defaultNodeHome := app.DefaultNodeHome

	// add Cosmos EVM key commands
	rootCmd.AddCommand(
		evmcosmoscmd.KeyCommands(defaultNodeHome, true),
	)

}

func addModuleInitFlags(startCmd *cobra.Command) {
	crisis.AddModuleInitFlags(startCmd)
	startCmd.Flags().StringVar(&c.EnclaveAddr, "enclave-addr", "", "address:port of enclave (e.g. localhost:50051)")
	startCmd.Flags().StringVar(&c.EnclaveSignerID, "enclave-signer-id", "", "signer-id of enclave")
	startCmd.Flags().StringVar(&c.EnclaveUniqueID, "enclave-unique-id", "", "unique-id of enclave")

}

// genesisCommand builds genesis-related `qadenad genesis` command. Users may provide application specific commands as a parameter
func genesisCommand(txConfig client.TxConfig, basicManager module.BasicManager, cmds ...*cobra.Command) *cobra.Command {
	cmd := genutilcli.Commands(txConfig, basicManager, app.DefaultNodeHome)

	for _, subCmd := range cmds {
		cmd.AddCommand(subCmd)
	}
	return cmd
}

func queryCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:                        "query",
		Aliases:                    []string{"q"},
		Short:                      "Querying subcommands",
		DisableFlagParsing:         false,
		SuggestionsMinimumDistance: 2,
		RunE:                       client.ValidateCmd,
	}

	cmd.AddCommand(
		rpc.QueryEventForTxCmd(),
		rpc.ValidatorCommand(),
		server.QueryBlockCmd(),
		authcmd.QueryTxsByEventsCmd(),
		server.QueryBlocksCmd(),
		authcmd.QueryTxCmd(),
		server.QueryBlockResultsCmd(),
	)
	cmd.PersistentFlags().String(flags.FlagChainID, "", "The network chain ID")

	return cmd
}

func txCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:                        "tx",
		Short:                      "Transactions subcommands",
		DisableFlagParsing:         false,
		SuggestionsMinimumDistance: 2,
		RunE:                       client.ValidateCmd,
	}

	cmd.AddCommand(
		authcmd.GetSignCommand(),
		authcmd.GetSignBatchCommand(),
		authcmd.GetMultiSignCommand(),
		authcmd.GetMultiSignBatchCmd(),
		authcmd.GetValidateSignaturesCommand(),
		flags.LineBreak,
		authcmd.GetBroadcastCommand(),
		authcmd.GetEncodeCommand(),
		authcmd.GetDecodeCommand(),
		authcmd.GetSimulateCmd(),
	)
	cmd.PersistentFlags().String(flags.FlagChainID, "", "The network chain ID")

	return cmd
}

// setEVMChainIDFromGenesis reads the Cosmos chain-id from genesis.json and
// derives the EVM chain ID, setting it in Viper so that all consumers
// (including the JSON-RPC backend) use the correct value.
func setEVMChainIDFromGenesis(appOpts servertypes.AppOptions) {
	evmChainID := cast.ToUint64(appOpts.Get(evmsrvflags.EVMChainID))
	if evmChainID != 0 && evmChainID != evmtypes.DefaultEVMChainID {
		return // already explicitly configured
	}

	v, ok := appOpts.(*viper.Viper)
	if !ok {
		return
	}

	// Read chain-id from genesis.json
	homePath := cast.ToString(appOpts.Get(flags.FlagHome))
	if homePath == "" {
		homePath = app.DefaultNodeHome
	}
	genFile := filepath.Join(homePath, "config", "genesis.json")
	appGenesis, err := genutiltypes.AppGenesisFromFile(genFile)
	if err != nil {
		return // genesis may not exist yet (e.g. during init)
	}

	// Parse numeric part from chain-id like "qadena_4444-1"
	cosmosChainID := appGenesis.ChainID
	parts := strings.Split(cosmosChainID, "_")
	if len(parts) != 2 {
		return
	}
	numParts := strings.Split(parts[1], "-")
	if len(numParts) != 2 {
		return
	}
	parsed := cast.ToUint64(numParts[0])
	if parsed == 0 {
		return
	}

	v.Set(evmsrvflags.EVMChainID, parsed)
}

// newApp creates the application
func newApp(
	logger log.Logger,
	db dbm.DB,
	traceStore io.Writer,
	appOpts servertypes.AppOptions,
) evmserver.Application {
	setEVMChainIDFromGenesis(appOpts)

	baseappOptions := server.DefaultBaseappOptions(appOpts)

	app, err := app.New(
		logger, db, traceStore, true,
		appOpts,
		[]wasmkeeper.Option{},
		baseappOptions...,
	)
	if err != nil {
		panic(err)
	}
	return app
}

// appExport creates a new app (optionally at a given height) and exports state.
func appExport(
	logger log.Logger,
	db dbm.DB,
	traceStore io.Writer,
	height int64,
	forZeroHeight bool,
	jailAllowedAddrs []string,
	appOpts servertypes.AppOptions,
	modulesToExport []string,
) (servertypes.ExportedApp, error) {
	var (
		bApp *app.App
		err  error
	)

	// this check is necessary as we use the flag in x/upgrade.
	// we can exit more gracefully by checking the flag here.
	homePath, ok := appOpts.Get(flags.FlagHome).(string)
	if !ok || homePath == "" {
		return servertypes.ExportedApp{}, errors.New("application home not set")
	}

	viperAppOpts, ok := appOpts.(*viper.Viper)
	if !ok {
		return servertypes.ExportedApp{}, errors.New("appOpts is not viper.Viper")
	}

	// overwrite the FlagInvCheckPeriod
	viperAppOpts.Set(server.FlagInvCheckPeriod, 1)
	appOpts = viperAppOpts

	if height != -1 {
		bApp, err = app.New(logger, db, traceStore, false, appOpts, []wasmkeeper.Option{})
		if err != nil {
			return servertypes.ExportedApp{}, err
		}

		if err := bApp.LoadHeight(height); err != nil {
			return servertypes.ExportedApp{}, err
		}
	} else {
		bApp, err = app.New(logger, db, traceStore, true, appOpts, []wasmkeeper.Option{})
		if err != nil {
			return servertypes.ExportedApp{}, err
		}
	}

	return bApp.ExportAppStateAndValidators(forZeroHeight, jailAllowedAddrs, modulesToExport)
}
