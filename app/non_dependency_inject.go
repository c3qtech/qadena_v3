package app

import (
	"errors"
	"strings"

	"cosmossdk.io/core/appmodule"
	storetypes "cosmossdk.io/store/types"
	cdctypes "github.com/cosmos/cosmos-sdk/codec/types"
	servertypes "github.com/cosmos/cosmos-sdk/server/types"
	"github.com/cosmos/cosmos-sdk/types/module"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	govtypes "github.com/cosmos/cosmos-sdk/x/gov/types"
	govv1beta1 "github.com/cosmos/cosmos-sdk/x/gov/types/v1beta1"
	paramstypes "github.com/cosmos/cosmos-sdk/x/params/types"

	//	"github.com/cosmos/ibc-go/modules/capability"
	//	capabilitykeeper "github.com/cosmos/ibc-go/modules/capability/keeper"
	//	capabilitytypes "github.com/cosmos/ibc-go/modules/capability/types"
	icamodule "github.com/cosmos/ibc-go/v10/modules/apps/27-interchain-accounts"
	icacontroller "github.com/cosmos/ibc-go/v10/modules/apps/27-interchain-accounts/controller"
	icacontrollerkeeper "github.com/cosmos/ibc-go/v10/modules/apps/27-interchain-accounts/controller/keeper"
	icacontrollertypes "github.com/cosmos/ibc-go/v10/modules/apps/27-interchain-accounts/controller/types"
	icahost "github.com/cosmos/ibc-go/v10/modules/apps/27-interchain-accounts/host"
	icahostkeeper "github.com/cosmos/ibc-go/v10/modules/apps/27-interchain-accounts/host/keeper"
	icahosttypes "github.com/cosmos/ibc-go/v10/modules/apps/27-interchain-accounts/host/types"
	icatypes "github.com/cosmos/ibc-go/v10/modules/apps/27-interchain-accounts/types"

	//ibcfee "github.com/cosmos/ibc-go/v10/modules/apps/29-fee"
	//ibcfeekeeper "github.com/cosmos/ibc-go/v10/modules/apps/29-fee/keeper"
	//ibcfeetypes "github.com/cosmos/ibc-go/v10/modules/apps/29-fee/types"
	"github.com/cosmos/cosmos-sdk/runtime"
	govkeeper "github.com/cosmos/cosmos-sdk/x/gov/keeper"
	"github.com/cosmos/cosmos-sdk/x/params"
	paramproposal "github.com/cosmos/cosmos-sdk/x/params/types/proposal"
	ibctransfer "github.com/cosmos/ibc-go/v10/modules/apps/transfer"
	ibctransfertypes "github.com/cosmos/ibc-go/v10/modules/apps/transfer/types"
	ibc "github.com/cosmos/ibc-go/v10/modules/core"
	ibcclienttypes "github.com/cosmos/ibc-go/v10/modules/core/02-client/types"
	ibcconnectiontypes "github.com/cosmos/ibc-go/v10/modules/core/03-connection/types"
	porttypes "github.com/cosmos/ibc-go/v10/modules/core/05-port/types"
	ibcexported "github.com/cosmos/ibc-go/v10/modules/core/exported"
	ibckeeper "github.com/cosmos/ibc-go/v10/modules/core/keeper"
	solomachine "github.com/cosmos/ibc-go/v10/modules/light-clients/06-solomachine"
	ibctm "github.com/cosmos/ibc-go/v10/modules/light-clients/07-tendermint"

	// this line is used by starport scaffolding # ibc/app/import
	"fmt"

	wasm "github.com/CosmWasm/wasmd/x/wasm"
	wasmkeeper "github.com/CosmWasm/wasmd/x/wasm/keeper"
	wasmtypes "github.com/CosmWasm/wasmd/x/wasm/types"
	distrkeeper "github.com/cosmos/cosmos-sdk/x/distribution/keeper"
	ibccallbacks "github.com/cosmos/ibc-go/v10/modules/apps/callbacks"

	//	"github.com/cosmos/ibc-go/v10/modules/apps/transfer"
	//	transferv2 "github.com/cosmos/ibc-go/v10/modules/apps/transfer/v2"

	ibcapi "github.com/cosmos/ibc-go/v10/modules/core/api"

	//	evmencoding "github.com/cosmos/evm/encoding"
	evmaddress "github.com/cosmos/evm/encoding/address"
	"github.com/cosmos/evm/ethereum/eip712"
	evmprecompiletypes "github.com/cosmos/evm/precompiles/types"
	evmsrvflags "github.com/cosmos/evm/server/flags"
	evmerc20 "github.com/cosmos/evm/x/erc20"
	evmerc20keeper "github.com/cosmos/evm/x/erc20/keeper"
	evmerc20types "github.com/cosmos/evm/x/erc20/types"
	evmerc20v2 "github.com/cosmos/evm/x/erc20/v2"
	evmfeemarket "github.com/cosmos/evm/x/feemarket"
	evmfeemarketkeeper "github.com/cosmos/evm/x/feemarket/keeper"
	evmfeemarkettypes "github.com/cosmos/evm/x/feemarket/types"

	evmprecisebank "github.com/cosmos/evm/x/precisebank"
	evmprecisebankkeeper "github.com/cosmos/evm/x/precisebank/keeper"
	evmprecisebanktypes "github.com/cosmos/evm/x/precisebank/types"
	evmvm "github.com/cosmos/evm/x/vm"
	evmkeeper "github.com/cosmos/evm/x/vm/keeper"
	evmtypes "github.com/cosmos/evm/x/vm/types"

	evmibctransferkeeper "github.com/cosmos/evm/x/ibc/transfer/keeper"

	evmibctransfer "github.com/cosmos/evm/x/ibc/transfer"

	evmibctransferv2 "github.com/cosmos/evm/x/ibc/transfer/v2"

	evmibccallbackskeeper "github.com/cosmos/evm/x/ibc/callbacks/keeper"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/spf13/cast"

	"path/filepath"
)

// registerIBCModules register IBC keepers and non dependency inject modules.
func (app *App) registerNonDependencyInjectModules(appOpts servertypes.AppOptions, wasmOpts []wasmkeeper.Option) error {
	// set up non depinject support modules store keys

	app.EVMTransientKeys = storetypes.NewTransientStoreKeys(
		evmtypes.TransientKey,
		evmfeemarkettypes.TransientKey,
	)

	app.EVMKeys = storetypes.NewKVStoreKeys(
		evmtypes.StoreKey,
		evmfeemarkettypes.StoreKey,
		evmerc20types.StoreKey,
		evmprecisebanktypes.StoreKey,
	)

	if err := app.RegisterStores(
		//		storetypes.NewKVStoreKey(capabilitytypes.StoreKey),
		storetypes.NewKVStoreKey(ibcexported.StoreKey),
		storetypes.NewKVStoreKey(ibctransfertypes.StoreKey),
		//		storetypes.NewKVStoreKey(ibcfeetypes.StoreKey),
		storetypes.NewKVStoreKey(icahosttypes.StoreKey),
		storetypes.NewKVStoreKey(icacontrollertypes.StoreKey),
		//		storetypes.NewMemoryStoreKey(capabilitytypes.MemStoreKey),
		storetypes.NewTransientStoreKey(paramstypes.TStoreKey),
		storetypes.NewKVStoreKey(wasmtypes.StoreKey),

		// Cosmos EVM transient and store keys
		app.EVMKeys[evmtypes.StoreKey],
		app.EVMKeys[evmfeemarkettypes.StoreKey],
		app.EVMKeys[evmerc20types.StoreKey],
		app.EVMKeys[evmprecisebanktypes.StoreKey],
		app.EVMTransientKeys[evmtypes.TransientKey],
		app.EVMTransientKeys[evmfeemarkettypes.TransientKey],
	); err != nil {
		return err
	}

	// register the key tables for legacy param subspaces
	keyTable := ibcclienttypes.ParamKeyTable()
	keyTable.RegisterParamSet(&ibcconnectiontypes.Params{})
	app.ParamsKeeper.Subspace(ibcexported.ModuleName).WithKeyTable(keyTable)
	app.ParamsKeeper.Subspace(ibctransfertypes.ModuleName).WithKeyTable(ibctransfertypes.ParamKeyTable())
	app.ParamsKeeper.Subspace(icacontrollertypes.SubModuleName).WithKeyTable(icacontrollertypes.ParamKeyTable())
	app.ParamsKeeper.Subspace(icahosttypes.SubModuleName).WithKeyTable(icahosttypes.ParamKeyTable())
	app.ParamsKeeper.Subspace(wasmtypes.ModuleName)

	/*
		// add capability keeper and ScopeToModule for ibc module
		app.CapabilityKeeper = capabilitykeeper.NewKeeper(
			app.AppCodec(),
			app.GetKey(capabilitytypes.StoreKey),
			app.GetMemKey(capabilitytypes.MemStoreKey),
		)

		// add capability keeper and ScopeToModule for ibc module
		scopedIBCKeeper := app.CapabilityKeeper.ScopeToModule(ibcexported.ModuleName)
		scopedIBCTransferKeeper := app.CapabilityKeeper.ScopeToModule(ibctransfertypes.ModuleName)
		scopedICAControllerKeeper := app.CapabilityKeeper.ScopeToModule(icacontrollertypes.SubModuleName)
		scopedICAHostKeeper := app.CapabilityKeeper.ScopeToModule(icahosttypes.SubModuleName)
	*/

	// Create IBC keeper
	app.IBCKeeper = ibckeeper.NewKeeper(
		app.appCodec,
		runtime.NewKVStoreService(app.GetKey(ibcexported.StoreKey)),
		app.GetSubspace(ibcexported.ModuleName),
		app.UpgradeKeeper,
		authtypes.NewModuleAddress(govtypes.ModuleName).String(),
	)

	// Register the proposal types
	// Deprecated: Avoid adding new handlers, instead use the new proposal flow
	// by granting the governance module the right to execute the message.
	// See: https://docs.cosmos.network/main/modules/gov#proposal-messages
	govRouter := govv1beta1.NewRouter()
	govRouter.AddRoute(govtypes.RouterKey, govv1beta1.ProposalHandler).
		AddRoute(paramproposal.RouterKey, params.NewParamChangeProposalHandler(app.ParamsKeeper))
	govConfig := govtypes.DefaultConfig()
	/*
		Example of setting gov params:
		govConfig.MaxMetadataLen = 10000
	*/
	govKeeper := govkeeper.NewKeeper(
		app.appCodec,
		runtime.NewKVStoreService(app.GetKey(govtypes.StoreKey)),
		app.AccountKeeper,
		app.BankKeeper,
		app.StakingKeeper,
		app.DistrKeeper,
		app.MsgServiceRouter(),
		govConfig,
		authtypes.NewModuleAddress(govtypes.ModuleName).String(),
	)

	// Set legacy router for backwards compatibility with gov v1beta1
	govKeeper.SetLegacyRouter(govRouter)

	app.GovKeeper = govKeeper.SetHooks(
		govtypes.NewMultiGovHooks(
		// register the governance hooks
		),
	)

	/* Replaced by EVM
	// Create Transfer Keepers
	app.TransferKeeper = ibctransferkeeper.NewKeeper(
		app.appCodec,
		runtime.NewKVStoreService(app.GetKey(ibctransfertypes.StoreKey)),
		app.GetSubspace(ibctransfertypes.ModuleName),
		app.IBCKeeper.ChannelKeeper,
		app.IBCKeeper.ChannelKeeper,
		app.MsgServiceRouter(),
		app.AccountKeeper,
		app.BankKeeper,
		authtypes.NewModuleAddress(govtypes.ModuleName).String(),
	)
	*/

	// Cosmos EVM keepers & modules

	evmChainID := cast.ToUint64(appOpts.Get(evmsrvflags.EVMChainID))
	if evmChainID == evmtypes.DefaultEVMChainID {
		// parse the chain-id from the genesis
		currentChainID := app.App.BaseApp.ChainID()
		// assume chain id looks like "qadena_4444-1", but parse it
		chainIDParts := strings.Split(currentChainID, "_")
		if len(chainIDParts) != 2 {
			return errors.New("invalid chain-id format")
		}
		// need to split the "4444-1" into "4444" and "1"
		chainIDParts = strings.Split(chainIDParts[1], "-")
		if len(chainIDParts) != 2 {
			return errors.New("invalid chain-id format")
		}
		evmChainID = cast.ToUint64(chainIDParts[0])
	}
	// log it
	app.Logger().Info("using evm chain-id", "chain-id", evmChainID)
	//	_ := evmencoding.MakeConfig(evmChainID)
	eip712.SetEncodingConfig(app.legacyAmino, app.interfaceRegistry, evmChainID)

	// EVM TODO, check what was added by evmencoding and check to make sure it's included in the "app." versions
	// EVM TODO, check what the effect of these are and do them for Qadena
	/*
		bApp := baseapp.NewBaseApp(
			appName,
			logger,
			db,
			// use transaction decoder to support the sdk.Tx interface instead of sdk.StdTx
			encodingConfig.TxConfig.TxDecoder(),
			baseAppOptions...,
		)
		bApp.SetCommitMultiStoreTracer(traceStore)
		bApp.SetVersion(version.Version)
		bApp.SetInterfaceRegistry(interfaceRegistry)
		bApp.SetTxEncoder(txConfig.TxEncoder())
	*/

	app.FeeMarketKeeper = evmfeemarketkeeper.NewKeeper(
		app.appCodec, authtypes.NewModuleAddress(govtypes.ModuleName),
		app.EVMKeys[evmfeemarkettypes.StoreKey],
		app.EVMTransientKeys[evmfeemarkettypes.TransientKey],
	)

	// Set up PreciseBank keeper
	//
	// NOTE: PreciseBank is not needed if SDK use 18 decimals for gas coin. Use BankKeeper instead.
	app.PreciseBankKeeper = evmprecisebankkeeper.NewKeeper(
		app.appCodec,
		app.EVMKeys[evmprecisebanktypes.StoreKey],
		app.BankKeeper,
		app.AccountKeeper,
	)

	// Set up EVM keeper
	tracer := cast.ToString(appOpts.Get(evmsrvflags.EVMTracer))

	// NOTE: it's required to set up the EVM keeper before the ERC-20 keeper, because it is used in its instantiation.
	app.EVMKeeper = evmkeeper.NewKeeper(
		// TODO: check why this is not adjusted to use the runtime module methods like SDK native keepers
		app.appCodec, app.EVMKeys[evmtypes.StoreKey], app.EVMTransientKeys[evmtypes.TransientKey], app.kvStoreKeys(),
		authtypes.NewModuleAddress(govtypes.ModuleName),
		app.AccountKeeper,
		app.PreciseBankKeeper,
		app.StakingKeeper,
		app.FeeMarketKeeper,
		&app.ConsensusParamsKeeper,
		&app.Erc20Keeper,
		evmChainID,
		tracer,
	).WithStaticPrecompiles(
		evmprecompiletypes.DefaultStaticPrecompiles(
			*app.StakingKeeper,
			app.DistrKeeper,
			app.PreciseBankKeeper,
			&app.Erc20Keeper,
			&app.EVMTransferKeeper,
			app.IBCKeeper.ChannelKeeper,
			*app.GovKeeper,
			app.SlashingKeeper,
			app.appCodec,
		),
	)

	app.Erc20Keeper = evmerc20keeper.NewKeeper(
		app.EVMKeys[evmerc20types.StoreKey],
		app.appCodec,
		authtypes.NewModuleAddress(govtypes.ModuleName),
		app.AccountKeeper,
		app.PreciseBankKeeper,
		app.EVMKeeper,
		app.StakingKeeper,
		&app.EVMTransferKeeper,
	)

	// instantiate IBC transfer keeper AFTER the ERC-20 keeper to use it in the instantiation

	// get authority address
	authAddr := authtypes.NewModuleAddress(govtypes.ModuleName).String()

	app.EVMTransferKeeper = evmibctransferkeeper.NewKeeper(
		app.appCodec,
		runtime.NewKVStoreService(app.GetKey(ibctransfertypes.StoreKey)),
		app.IBCKeeper.ChannelKeeper,
		app.IBCKeeper.ChannelKeeper,
		app.MsgServiceRouter(),
		app.AccountKeeper,
		app.BankKeeper,
		app.Erc20Keeper, // Add ERC20 Keeper for ERC20 transfers
		authAddr,
	)
	app.EVMTransferKeeper.SetAddressCodec(evmaddress.NewEvmCodec(sdk.GetConfig().GetBech32AccountAddrPrefix()))

	app.ICAHostKeeper = icahostkeeper.NewKeeper(
		app.appCodec,
		runtime.NewKVStoreService(app.GetKey(icahosttypes.StoreKey)),
		app.GetSubspace(icahosttypes.SubModuleName),
		app.IBCKeeper.ChannelKeeper,
		app.IBCKeeper.ChannelKeeper,
		app.AccountKeeper,
		app.MsgServiceRouter(),
		app.GRPCQueryRouter(), // set grpc router for ica host
		authAddr,
	)

	app.ICAControllerKeeper = icacontrollerkeeper.NewKeeper(
		app.appCodec,
		runtime.NewKVStoreService(app.GetKey(icacontrollertypes.StoreKey)),
		app.GetSubspace(icacontrollertypes.SubModuleName),
		app.IBCKeeper.ChannelKeeper,
		app.IBCKeeper.ChannelKeeper,
		app.MsgServiceRouter(),
		authAddr,
	)

	wasmDir := filepath.Join(DefaultNodeHome, "wasm")
	nodeConfig, err := wasm.ReadNodeConfig(appOpts)
	if err != nil {
		panic(fmt.Sprintf("error while reading wasm config: %s", err))
	}

	// The last arguments can contain custom message handlers, and custom query handlers,
	// if we want to allow any custom callbacks
	app.WasmKeeper = wasmkeeper.NewKeeper(
		app.appCodec,
		runtime.NewKVStoreService(app.GetKey(wasmtypes.StoreKey)),
		app.AccountKeeper,
		app.BankKeeper,
		app.StakingKeeper,
		distrkeeper.NewQuerier(app.DistrKeeper),
		app.IBCKeeper.ChannelKeeper,
		app.IBCKeeper.ChannelKeeper,
		app.EVMTransferKeeper,
		app.MsgServiceRouter(),
		app.GRPCQueryRouter(),
		wasmDir,
		nodeConfig,
		wasmtypes.VMConfig{},
		wasmkeeper.BuiltInCapabilities(),
		authtypes.NewModuleAddress(govtypes.ModuleName).String(),
		wasmOpts...,
	)

	// Create fee enabled wasm ibc Stack
	//	wasmStackIBCHandler := wasm.NewIBCHandler(app.WasmKeeper, app.IBCKeeper.ChannelKeeper, app.IBCKeeper.ChannelKeeper)

	app.EVMIBCCallbackKeeper = evmibccallbackskeeper.NewKeeper(
		app.AccountKeeper,
		app.EVMKeeper,
		app.Erc20Keeper,
	)
	evmMaxCallbackGas := uint64(1_000_000)

	// Create Interchain Accounts Stack
	// SendPacket, since it is originating from the application to core IBC:
	// icaAuthModuleKeeper.SendTx -> icaController.SendPacket -> fee.SendPacket -> channel.SendPacket
	var icaControllerStack porttypes.IBCModule
	// integration point for custom authentication modules
	// see https://medium.com/the-interchain-foundation/ibc-go-v6-changes-to-interchain-accounts-and-how-it-impacts-your-chain-806c185300d7
	var noAuthzModule porttypes.IBCModule
	icaControllerStack = icacontroller.NewIBCMiddlewareWithAuth(noAuthzModule, app.ICAControllerKeeper)
	icaControllerStack = icacontroller.NewIBCMiddlewareWithAuth(icaControllerStack, app.ICAControllerKeeper)
	icaControllerStack = ibccallbacks.NewIBCMiddleware(icaControllerStack, app.IBCKeeper.ChannelKeeper, app.EVMIBCCallbackKeeper, evmMaxCallbackGas)
	icaICS4Wrapper := icaControllerStack.(porttypes.ICS4Wrapper)
	// Since the callbacks middleware itself is an ics4wrapper, it needs to be passed to the ica controller keeper
	app.ICAControllerKeeper.WithICS4Wrapper(icaICS4Wrapper)

	// RecvPacket, message that originates from core IBC and goes down to app, the flow is:
	// channel.RecvPacket -> icaHost.OnRecvPacket
	icaHostStack := icahost.NewIBCModule(app.ICAHostKeeper)

	// Create Transfer Stack
	var transferStack porttypes.IBCModule

	transferStack = evmibctransfer.NewIBCModule(app.EVMTransferKeeper)
	transferStack = evmerc20.NewIBCMiddleware(app.Erc20Keeper, transferStack)

	transferStack = ibccallbacks.NewIBCMiddleware(transferStack, app.IBCKeeper.ChannelKeeper, app.EVMIBCCallbackKeeper, evmMaxCallbackGas)
	transferICS4Wrapper := transferStack.(porttypes.ICS4Wrapper)
	// Since the callbacks middleware itself is an ics4wrapper, it needs to be passed to the ica controller keeper
	app.EVMTransferKeeper.WithICS4Wrapper(transferICS4Wrapper)

	var transferStackV2 ibcapi.IBCModule
	transferStackV2 = evmibctransferv2.NewIBCModule(app.EVMTransferKeeper)
	transferStackV2 = evmerc20v2.NewIBCMiddleware(transferStackV2, app.Erc20Keeper)

	// Create static IBC router, add app routes, then set and seal it
	ibcRouter := porttypes.NewRouter().
		AddRoute(ibctransfertypes.ModuleName, transferStack).
		AddRoute(icacontrollertypes.SubModuleName, icaControllerStack).
		AddRoute(icahosttypes.SubModuleName, icaHostStack)
	app.IBCKeeper.SetRouter(ibcRouter)

	ibcRouterV2 := ibcapi.NewRouter().
		AddRoute(ibctransfertypes.ModuleName, transferStackV2)
	app.IBCKeeper.SetRouterV2(ibcRouterV2)

	clientKeeper := app.IBCKeeper.ClientKeeper
	storeProvider := app.IBCKeeper.ClientKeeper.GetStoreProvider()

	tmLightClientModule := ibctm.NewLightClientModule(app.appCodec, storeProvider)
	clientKeeper.AddRoute(ibctm.ModuleName, &tmLightClientModule)

	soloLightClientModule := solomachine.NewLightClientModule(app.appCodec, storeProvider)
	clientKeeper.AddRoute(solomachine.ModuleName, &soloLightClientModule)

	// Override the ICS20 app module
	transferModule := evmibctransfer.NewAppModule(app.EVMTransferKeeper)

	// register non-dependency-inject modules
	if err := app.RegisterModules(
		// wasm module
		wasm.NewAppModule(app.appCodec, &app.WasmKeeper, app.StakingKeeper, app.AccountKeeper, app.BankKeeper, app.MsgServiceRouter(), app.GetSubspace(wasmtypes.ModuleName)),
		// ibc modules
		ibc.NewAppModule(app.IBCKeeper),
		ibctm.NewAppModule(tmLightClientModule),
		transferModule,
		// ica module
		icamodule.NewAppModule(&app.ICAControllerKeeper, &app.ICAHostKeeper),
		// solomachine module
		solomachine.NewAppModule(soloLightClientModule),

		// Cosmos EVM modules
		evmvm.NewAppModule(app.EVMKeeper, app.AccountKeeper, app.BankKeeper, app.AccountKeeper.AddressCodec()),
		evmfeemarket.NewAppModule(app.FeeMarketKeeper),
		evmerc20.NewAppModule(app.Erc20Keeper, app.AccountKeeper),
		evmprecisebank.NewAppModule(app.PreciseBankKeeper, app.BankKeeper, app.AccountKeeper),
	); err != nil {
		return err
	}

	return nil
}

// RegisterNonDependencyInjectRegistryInterfaces Since the some modules don't support dependency injection,
// we need to manually register the modules on the client side.
// This needs to be removed after IBC supports App Wiring.
func RegisterNonDependencyInjectRegistryInterfaces(registry cdctypes.InterfaceRegistry) map[string]appmodule.AppModule {
	modules := map[string]appmodule.AppModule{
		ibcexported.ModuleName:      ibc.AppModule{},
		ibctransfertypes.ModuleName: ibctransfer.AppModule{},
		icatypes.ModuleName:         icamodule.AppModule{},
		ibctm.ModuleName:            ibctm.AppModule{},
		solomachine.ModuleName:      solomachine.AppModule{},
		wasmtypes.ModuleName:        wasm.AppModule{},
		// evm modules
		evmfeemarkettypes.ModuleName:   evmfeemarket.AppModule{},
		evmprecisebanktypes.ModuleName: evmprecisebank.AppModule{},
		evmtypes.ModuleName:            evmvm.AppModule{},
		evmerc20types.ModuleName:       evmerc20.AppModule{},
	}

	for name, m := range modules {
		module.CoreAppModuleBasicAdaptor(name, m).RegisterInterfaces(registry)
	}

	return modules
}
