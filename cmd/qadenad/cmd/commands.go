package cmd

import (
	"errors"
	"io"

	"cosmossdk.io/log"
	confixcmd "cosmossdk.io/tools/confix/cmd"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/cosmos/cosmos-sdk/client"

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

	evmcosmosserverconfig "github.com/cosmos/evm/server/config"
	evmsrvflags "github.com/cosmos/evm/server/flags"
)

func initRootCmd(
	rootCmd *cobra.Command,
	txConfig client.TxConfig,
	basicManager module.BasicManager,
) {
	rootCmd.AddCommand(
		genutilcli.InitCmd(basicManager, app.DefaultNodeHome),
		evmdebug.Cmd(), // EVM
		//		debug.Cmd(), -- replaced by above
		confixcmd.ConfigCommand(),
		pruning.Cmd(newApp, app.DefaultNodeHome),
		snapshot.Cmd(newApp),
	)

	server.AddCommands(rootCmd, app.DefaultNodeHome, newApp, appExport, addModuleInitFlags)

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

	addEVMModuleInitFlags(startCmd)
}

func addEVMModuleInitFlags(startCmd *cobra.Command) {
	startCmd.Flags().Bool(evmsrvflags.JSONRPCEnable, evmcosmosserverconfig.DefaultJSONRPCEnable, "Define if the JSON-RPC server should be enabled")
	startCmd.Flags().StringSlice(evmsrvflags.JSONRPCAPI, evmcosmosserverconfig.GetDefaultAPINamespaces(), "Defines a list of JSON-RPC namespaces that should be enabled")
	startCmd.Flags().String(evmsrvflags.JSONRPCAddress, evmcosmosserverconfig.DefaultJSONRPCAddress, "the JSON-RPC server address to listen on")
	startCmd.Flags().String(evmsrvflags.JSONWsAddress, evmcosmosserverconfig.DefaultJSONRPCWsAddress, "the JSON-RPC WS server address to listen on")
	startCmd.Flags().StringSlice(evmsrvflags.JSONRPCWSOrigins, evmcosmosserverconfig.GetDefaultWSOrigins(), "Defines a list of WebSocket origins that should be allowed to connect")
	startCmd.Flags().Uint64(evmsrvflags.JSONRPCGasCap, evmcosmosserverconfig.DefaultGasCap, "Sets a cap on gas that can be used in eth_call/estimateGas unit is aatom (0=infinite)")                         //nolint:lll
	startCmd.Flags().Bool(evmsrvflags.JSONRPCAllowInsecureUnlock, evmcosmosserverconfig.DefaultJSONRPCAllowInsecureUnlock, "Allow insecure account unlocking when account-related RPCs are exposed by http") //nolint:lll
	startCmd.Flags().Float64(evmsrvflags.JSONRPCTxFeeCap, evmcosmosserverconfig.DefaultTxFeeCap, "Sets a cap on transaction fee that can be sent via the RPC APIs (1 = default 1 evmos)")                    //nolint:lll
	startCmd.Flags().Int32(evmsrvflags.JSONRPCFilterCap, evmcosmosserverconfig.DefaultFilterCap, "Sets the global cap for total number of filters that can be created")
	startCmd.Flags().Duration(evmsrvflags.JSONRPCEVMTimeout, evmcosmosserverconfig.DefaultEVMTimeout, "Sets a timeout used for eth_call (0=infinite)")
	startCmd.Flags().Duration(evmsrvflags.JSONRPCHTTPTimeout, evmcosmosserverconfig.DefaultHTTPTimeout, "Sets a read/write timeout for json-rpc http server (0=infinite)")
	startCmd.Flags().Duration(evmsrvflags.JSONRPCHTTPIdleTimeout, evmcosmosserverconfig.DefaultHTTPIdleTimeout, "Sets a idle timeout for json-rpc http server (0=infinite)")
	startCmd.Flags().Bool(evmsrvflags.JSONRPCAllowUnprotectedTxs, evmcosmosserverconfig.DefaultAllowUnprotectedTxs, "Allow for unprotected (non EIP155 signed) transactions to be submitted via the node's RPC when the global parameter is disabled") //nolint:lll
	startCmd.Flags().Int(evmsrvflags.JSONRPCBatchRequestLimit, evmcosmosserverconfig.DefaultBatchRequestLimit, "Maximum number of requests in a batch")
	startCmd.Flags().Int(evmsrvflags.JSONRPCBatchResponseMaxSize, evmcosmosserverconfig.DefaultBatchResponseMaxSize, "Maximum size of server response")
	startCmd.Flags().Int32(evmsrvflags.JSONRPCLogsCap, evmcosmosserverconfig.DefaultLogsCap, "Sets the max number of results can be returned from single `eth_getLogs` query")
	startCmd.Flags().Int32(evmsrvflags.JSONRPCBlockRangeCap, evmcosmosserverconfig.DefaultBlockRangeCap, "Sets the max block range allowed for `eth_getLogs` query")
	startCmd.Flags().Int(evmsrvflags.JSONRPCMaxOpenConnections, evmcosmosserverconfig.DefaultMaxOpenConnections, "Sets the maximum number of simultaneous connections for the server listener") //nolint:lll
	startCmd.Flags().Bool(evmsrvflags.JSONRPCEnableIndexer, false, "Enable the custom tx indexer for json-rpc")
	startCmd.Flags().Bool(evmsrvflags.JSONRPCEnableMetrics, false, "Define if EVM rpc metrics server should be enabled")
	startCmd.Flags().Bool(evmsrvflags.JSONRPCEnableProfiling, false, "Enables the profiling in the debug namespace")

	startCmd.Flags().String(evmsrvflags.EVMTracer, evmcosmosserverconfig.DefaultEVMTracer, "the EVM tracer type to collect execution traces from the EVM transaction execution (json|struct|access_list|markdown)") //nolint:lll
	startCmd.Flags().Uint64(evmsrvflags.EVMMaxTxGasWanted, evmcosmosserverconfig.DefaultMaxTxGasWanted, "the gas wanted for each eth tx returned in ante handler in check tx mode")                                 //nolint:lll
	startCmd.Flags().Bool(evmsrvflags.EVMEnablePreimageRecording, evmcosmosserverconfig.DefaultEnablePreimageRecording, "Enables tracking of SHA3 preimages in the EVM (not implemented yet)")                      //nolint:lll
	startCmd.Flags().Uint64(evmsrvflags.EVMChainID, evmcosmosserverconfig.DefaultEVMChainID, "the EIP-155 compatible replay protection chain ID")
	startCmd.Flags().Uint64(evmsrvflags.EVMMinTip, evmcosmosserverconfig.DefaultEVMMinTip, "the minimum priority fee for the mempool")
	startCmd.Flags().String(evmsrvflags.EvmGethMetricsAddress, evmcosmosserverconfig.DefaultGethMetricsAddress, "the address to bind the geth metrics server to")

	startCmd.Flags().Uint64(evmsrvflags.EVMMempoolPriceLimit, evmcosmosserverconfig.DefaultMempoolConfig().PriceLimit, "the minimum gas price to enforce for acceptance into the pool (in wei)")
	startCmd.Flags().Uint64(evmsrvflags.EVMMempoolPriceBump, evmcosmosserverconfig.DefaultMempoolConfig().PriceBump, "the minimum price bump percentage to replace an already existing transaction (nonce)")
	startCmd.Flags().Uint64(evmsrvflags.EVMMempoolAccountSlots, evmcosmosserverconfig.DefaultMempoolConfig().AccountSlots, "the number of executable transaction slots guaranteed per account")
	startCmd.Flags().Uint64(evmsrvflags.EVMMempoolGlobalSlots, evmcosmosserverconfig.DefaultMempoolConfig().GlobalSlots, "the maximum number of executable transaction slots for all accounts")
	startCmd.Flags().Uint64(evmsrvflags.EVMMempoolAccountQueue, evmcosmosserverconfig.DefaultMempoolConfig().AccountQueue, "the maximum number of non-executable transaction slots permitted per account")
	startCmd.Flags().Uint64(evmsrvflags.EVMMempoolGlobalQueue, evmcosmosserverconfig.DefaultMempoolConfig().GlobalQueue, "the maximum number of non-executable transaction slots for all accounts")
	startCmd.Flags().Duration(evmsrvflags.EVMMempoolLifetime, evmcosmosserverconfig.DefaultMempoolConfig().Lifetime, "the maximum amount of time non-executable transaction are queued")

	startCmd.Flags().String(evmsrvflags.TLSCertPath, "", "the cert.pem file path for the server TLS configuration")
	startCmd.Flags().String(evmsrvflags.TLSKeyPath, "", "the key.pem file path for the server TLS configuration")
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

// newApp creates the application
func newApp(
	logger log.Logger,
	db dbm.DB,
	traceStore io.Writer,
	appOpts servertypes.AppOptions,
) servertypes.Application {
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
