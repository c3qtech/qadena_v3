package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	abci "github.com/cometbft/cometbft/abci/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	_ "cosmossdk.io/api/cosmos/tx/config/v1" // import for side-effects
	"cosmossdk.io/core/address"
	"cosmossdk.io/depinject"
	"cosmossdk.io/log"

	//	"cosmossdk.io/math"
	storetypes "cosmossdk.io/store/types"
	_ "cosmossdk.io/x/circuit" // import for side-effects
	circuitkeeper "cosmossdk.io/x/circuit/keeper"
	_ "cosmossdk.io/x/evidence" // import for side-effects
	evidencekeeper "cosmossdk.io/x/evidence/keeper"
	feegrantkeeper "cosmossdk.io/x/feegrant/keeper"
	_ "cosmossdk.io/x/feegrant/module" // import for side-effects
	nftkeeper "cosmossdk.io/x/nft/keeper"
	_ "cosmossdk.io/x/nft/module" // import for side-effects
	_ "cosmossdk.io/x/upgrade"    // import for side-effects
	upgradekeeper "cosmossdk.io/x/upgrade/keeper"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/cosmos/cosmos-sdk/baseapp"
	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/runtime"
	"github.com/cosmos/cosmos-sdk/server"
	"github.com/cosmos/cosmos-sdk/server/api"
	"github.com/cosmos/cosmos-sdk/server/config"
	servertypes "github.com/cosmos/cosmos-sdk/server/types"
	"github.com/cosmos/cosmos-sdk/types/module"
	"github.com/cosmos/cosmos-sdk/x/auth"
	_ "github.com/cosmos/cosmos-sdk/x/auth" // import for side-effects
	authkeeper "github.com/cosmos/cosmos-sdk/x/auth/keeper"
	authsims "github.com/cosmos/cosmos-sdk/x/auth/simulation"
	_ "github.com/cosmos/cosmos-sdk/x/auth/tx/config" // import for side-effects
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	_ "github.com/cosmos/cosmos-sdk/x/auth/vesting" // import for side-effects
	authzkeeper "github.com/cosmos/cosmos-sdk/x/authz/keeper"
	_ "github.com/cosmos/cosmos-sdk/x/authz/module" // import for side-effects
	_ "github.com/cosmos/cosmos-sdk/x/bank"         // import for side-effects
	bankkeeper "github.com/cosmos/cosmos-sdk/x/bank/keeper"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	_ "github.com/cosmos/cosmos-sdk/x/consensus" // import for side-effects
	consensuskeeper "github.com/cosmos/cosmos-sdk/x/consensus/keeper"
	_ "github.com/cosmos/cosmos-sdk/x/distribution" // import for side-effects
	distrkeeper "github.com/cosmos/cosmos-sdk/x/distribution/keeper"
	"github.com/cosmos/cosmos-sdk/x/genutil"
	genutiltypes "github.com/cosmos/cosmos-sdk/x/genutil/types"
	"github.com/cosmos/cosmos-sdk/x/gov"
	govclient "github.com/cosmos/cosmos-sdk/x/gov/client"
	govkeeper "github.com/cosmos/cosmos-sdk/x/gov/keeper"
	govtypes "github.com/cosmos/cosmos-sdk/x/gov/types"
	groupkeeper "github.com/cosmos/cosmos-sdk/x/group/keeper"
	_ "github.com/cosmos/cosmos-sdk/x/group/module" // import for side-effects
	_ "github.com/cosmos/cosmos-sdk/x/mint"         // import for side-effects
	mintkeeper "github.com/cosmos/cosmos-sdk/x/mint/keeper"
	_ "github.com/cosmos/cosmos-sdk/x/params" // import for side-effects
	paramsclient "github.com/cosmos/cosmos-sdk/x/params/client"
	paramskeeper "github.com/cosmos/cosmos-sdk/x/params/keeper"
	paramstypes "github.com/cosmos/cosmos-sdk/x/params/types"
	_ "github.com/cosmos/cosmos-sdk/x/slashing" // import for side-effects
	slashingkeeper "github.com/cosmos/cosmos-sdk/x/slashing/keeper"
	_ "github.com/cosmos/cosmos-sdk/x/staking" // import for side-effects
	stakingkeeper "github.com/cosmos/cosmos-sdk/x/staking/keeper"
	"github.com/spf13/cast"

	//	_ "github.com/cosmos/ibc-go/modules/capability" // import for side-effects
	//	capabilitykeeper "github.com/cosmos/ibc-go/modules/capability/keeper"
	_ "github.com/cosmos/ibc-go/v10/modules/apps/27-interchain-accounts" // import for side-effects
	icacontrollerkeeper "github.com/cosmos/ibc-go/v10/modules/apps/27-interchain-accounts/controller/keeper"
	icahostkeeper "github.com/cosmos/ibc-go/v10/modules/apps/27-interchain-accounts/host/keeper"

	// _ "github.com/cosmos/ibc-go/v10/modules/apps/29-fee" // import for side-effects
	//ibcfeekeeper "github.com/cosmos/ibc-go/v10/modules/apps/29-fee/keeper"
	ibctransferkeeper "github.com/cosmos/ibc-go/v10/modules/apps/transfer/keeper"
	ibckeeper "github.com/cosmos/ibc-go/v10/modules/core/keeper"

	ibctransfer "github.com/cosmos/ibc-go/v10/modules/apps/transfer"
	ibctransfertypes "github.com/cosmos/ibc-go/v10/modules/apps/transfer/types"

	ibctesting "github.com/cosmos/ibc-go/v10/testing"

	nameservicemodulekeeper "github.com/c3qtech/qadena_v3/x/nameservice/keeper"
	qadenamodulekeeper "github.com/c3qtech/qadena_v3/x/qadena/keeper"
	qadenatypes "github.com/c3qtech/qadena_v3/x/qadena/types"

	dsvsmodulekeeper "github.com/c3qtech/qadena_v3/x/dsvs/keeper"
	pricefeedmodulekeeper "github.com/c3qtech/qadena_v3/x/pricefeed/keeper"

	// CosmWasm
	wasmkeeper "github.com/CosmWasm/wasmd/x/wasm/keeper"
	wasmtypes "github.com/CosmWasm/wasmd/x/wasm/types"

	// sdk 53.5
	upgradetypes "cosmossdk.io/x/upgrade/types"
	epochskeeper "github.com/cosmos/cosmos-sdk/x/epochs/keeper"
	epochstypes "github.com/cosmos/cosmos-sdk/x/epochs/types"
	protocolpoolkeeper "github.com/cosmos/cosmos-sdk/x/protocolpool/keeper"
	protocolpooltypes "github.com/cosmos/cosmos-sdk/x/protocolpool/types"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"

	cosmossdkversion "github.com/cosmos/cosmos-sdk/version"

	// this line is used by starport scaffolding # stargate/app/moduleImport

	"github.com/c3qtech/qadena_v3/docs"

	//	sdkante "github.com/cosmos/cosmos-sdk/x/auth/ante"
	// 	qadena
	//	ante "github.com/c3qtech/qadena_v3/app/ante"
	post "github.com/c3qtech/qadena_v3/app/post"

	//	cmdcfg "github.com/c3qtech/qadena_v3/cmd/config"

	sdk "github.com/cosmos/cosmos-sdk/types"

	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"

	txsigning "cosmossdk.io/x/tx/signing"

	sdkmempool "github.com/cosmos/cosmos-sdk/types/mempool"

	// EVM
	evmante "github.com/cosmos/evm/ante"
	evmantetypes "github.com/cosmos/evm/ante/types"
	evmcryptocodec "github.com/cosmos/evm/crypto/codec"
	evmaddress "github.com/cosmos/evm/encoding/address"
	evmeip712 "github.com/cosmos/evm/ethereum/eip712"
	evmmempool "github.com/cosmos/evm/mempool"
	evmsrvflags "github.com/cosmos/evm/server/flags"
	evmutils "github.com/cosmos/evm/utils"
	evmerc20keeper "github.com/cosmos/evm/x/erc20/keeper"
	evmerc20types "github.com/cosmos/evm/x/erc20/types"
	evmfeemarketkeeper "github.com/cosmos/evm/x/feemarket/keeper"
	evmibccallbackskeeper "github.com/cosmos/evm/x/ibc/callbacks/keeper"
	evmibctransfer "github.com/cosmos/evm/x/ibc/transfer"
	evmibctransferkeeper "github.com/cosmos/evm/x/ibc/transfer/keeper"
	evmprecisebankkeeper "github.com/cosmos/evm/x/precisebank/keeper"
	evmkeeper "github.com/cosmos/evm/x/vm/keeper"
	evmtypes "github.com/cosmos/evm/x/vm/types"

	// Force-load the tracer engines to trigger registration due to Go-Ethereum v1.10.15 changes
	evmcommon "github.com/ethereum/go-ethereum/common"
	corevm "github.com/ethereum/go-ethereum/core/vm"
	_ "github.com/ethereum/go-ethereum/eth/tracers/js"
	_ "github.com/ethereum/go-ethereum/eth/tracers/native"
)

const (
	AccountAddressPrefix = "qadena"
	Name                 = "qadena"
)

var (
	// DefaultNodeHome default home directories for the application daemon
	DefaultNodeHome string
)

var (
	_ runtime.AppI            = (*App)(nil)
	_ servertypes.Application = (*App)(nil)
	_ ibctesting.TestingApp   = (*App)(nil)
)

// App extends an ABCI application, but with most of its parameters exported.
// They are exported for convenience in creating helper functions, as object
// capabilities aren't needed for testing.
type App struct {
	*runtime.App
	legacyAmino       *codec.LegacyAmino
	appCodec          codec.Codec
	txConfig          client.TxConfig
	nodeConfig        wasmtypes.NodeConfig
	interfaceRegistry codectypes.InterfaceRegistry

	clientCtx client.Context

	// Peers this node was told to state-sync from (config.toml statesync.rpc_servers), captured at
	// construction because OfferSnapshot needs them BEFORE there is any chain state to read peers
	// from.  Empty when state-sync is not configured, which is also when OfferSnapshot never runs.
	stateSyncRPCServers []string

	// keepers
	AccountKeeper         authkeeper.AccountKeeper
	BankKeeper            bankkeeper.Keeper
	StakingKeeper         *stakingkeeper.Keeper
	DistrKeeper           distrkeeper.Keeper
	ConsensusParamsKeeper consensuskeeper.Keeper

	SlashingKeeper       slashingkeeper.Keeper
	MintKeeper           mintkeeper.Keeper
	GovKeeper            *govkeeper.Keeper
	UpgradeKeeper        *upgradekeeper.Keeper
	ParamsKeeper         paramskeeper.Keeper
	AuthzKeeper          authzkeeper.Keeper
	EvidenceKeeper       evidencekeeper.Keeper
	FeeGrantKeeper       feegrantkeeper.Keeper
	GroupKeeper          groupkeeper.Keeper
	NFTKeeper            nftkeeper.Keeper
	CircuitBreakerKeeper circuitkeeper.Keeper

	// IBC
	IBCKeeper *ibckeeper.Keeper // IBC Keeper must be a pointer in the app, so we can SetRouter on it correctly
	// CapabilityKeeper *capabilitykeeper.Keeper
	//	IBCFeeKeeper        ibcfeekeeper.Keeper
	ICAControllerKeeper icacontrollerkeeper.Keeper
	ICAHostKeeper       icahostkeeper.Keeper
	TransferKeeper      ibctransferkeeper.Keeper

	// Scoped IBC
	//	ScopedIBCKeeper           capabilitykeeper.ScopedKeeper
	//	ScopedIBCTransferKeeper   capabilitykeeper.ScopedKeeper
	//	ScopedICAControllerKeeper capabilitykeeper.ScopedKeeper
	//	ScopedICAHostKeeper       capabilitykeeper.ScopedKeeper

	QadenaKeeper      qadenamodulekeeper.Keeper
	NameserviceKeeper nameservicemodulekeeper.Keeper
	PricefeedKeeper   pricefeedmodulekeeper.Keeper
	DsvsKeeper        dsvsmodulekeeper.Keeper
	// this line is used by starport scaffolding # stargate/app/keeperDeclaration

	WasmKeeper wasmkeeper.Keeper

	// sdk 53.5
	ProtocolPoolKeeper protocolpoolkeeper.Keeper
	EpochsKeeper       epochskeeper.Keeper

	// evm
	EVMPendingTxListeners []evmante.PendingTxListener
	EVMTransferKeeper     evmibctransferkeeper.Keeper
	EVMIBCCallbackKeeper  evmibccallbackskeeper.ContractKeeper

	// Cosmos EVM keepers
	FeeMarketKeeper   evmfeemarketkeeper.Keeper
	EVMKeeper         *evmkeeper.Keeper
	Erc20Keeper       evmerc20keeper.Keeper
	PreciseBankKeeper evmprecisebankkeeper.Keeper
	EVMMempool        *evmmempool.ExperimentalEVMMempool
	EVMTransientKeys  map[string]*storetypes.TransientStoreKey
	EVMKeys           map[string]*storetypes.KVStoreKey

	// simulation manager
	sm *module.SimulationManager
}

func init() {

	// set power reduction (replaced this with evmutils.AttoPowerReduction, which is the same anyway)
	//sdk.DefaultPowerReduction = math.NewIntFromUint64(1000000000000000000)

	// manually update the power reduction by replacing micro (u) -> atto (a) evmos
	sdk.DefaultPowerReduction = evmutils.AttoPowerReduction

	qadenaHome := os.Getenv("QADENAHOME")
	if qadenaHome != "" {
		DefaultNodeHome = qadenaHome
		return
	}

	userHomeDir, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}

	DefaultNodeHome = filepath.Join(userHomeDir, Name)
}

// GetTxConfig implements the TestingApp interface.
func (app *App) GetTxConfig() client.TxConfig {
	return app.txConfig
}

// getGovProposalHandlers return the chain proposal handlers.
func getGovProposalHandlers() []govclient.ProposalHandler {
	var govProposalHandlers []govclient.ProposalHandler
	// this line is used by starport scaffolding # stargate/app/govProposalHandlers

	govProposalHandlers = append(govProposalHandlers,
		paramsclient.ProposalHandler,
		// this line is used by starport scaffolding # stargate/app/govProposalHandler
	)

	return govProposalHandlers
}

// AppConfig returns the default app config.
func AppConfig() depinject.Config {
	return depinject.Configs(
		appConfig,
		// Loads the app config from a YAML file.
		// appconfig.LoadYAML(AppConfigYAML),
		depinject.Supply(
			// supply custom module basics
			map[string]module.AppModuleBasic{
				genutiltypes.ModuleName:     genutil.NewAppModuleBasic(genutiltypes.DefaultMessageValidator),
				govtypes.ModuleName:         gov.NewAppModuleBasic(getGovProposalHandlers()),
				ibctransfertypes.ModuleName: evmibctransfer.AppModuleBasic{AppModuleBasic: &ibctransfer.AppModuleBasic{}},

				// this line is used by starport scaffolding # stargate/appConfig/moduleBasic
			},

			// Cosmos EVM: supply address codec factories so ProvideAddressCodec
			// uses EVM-compatible codecs instead of the default bech32 ones.
			func() address.Codec {
				return evmaddress.NewEvmCodec(sdk.GetConfig().GetBech32AccountAddrPrefix())
			},
			func() runtime.ValidatorAddressCodec {
				return runtime.ValidatorAddressCodec(evmaddress.NewEvmCodec(sdk.GetConfig().GetBech32ValidatorAddrPrefix()))
			},
			func() runtime.ConsensusAddressCodec {
				return runtime.ConsensusAddressCodec(evmaddress.NewEvmCodec(sdk.GetConfig().GetBech32ConsensusAddrPrefix()))
			},
		),
		depinject.Provide(
			ProvideEVMCustomGetSigner,
			//			ProvideERC20CustomGetSigner,
		),
	)
}

func ProvideEVMCustomGetSigner() txsigning.CustomGetSigner {
	return evmtypes.MsgEthereumTxCustomGetSigner
}

func ProvideERC20CustomGetSigner() txsigning.CustomGetSigner {
	return evmerc20types.MsgConvertERC20CustomGetSigner
}

const UpgradeName = "v050-to-v053"

// historicalUpgradeNames lists every version-named upgrade plan that has ever been APPLIED on a
// qadena chain.  Append one entry per shipped plan; the --via-governance preflight asserts the
// previous plan was recorded here before it will schedule a new one.
//
// WHY A MAINTAINED LIST EXISTS when the two dynamic registrations below cover the common cases:
// x/upgrade's PreBlocker refuses to start ("upgrade handler is missing for %s upgrade plan") when
// the LAST APPLIED plan -- read from CHAIN STATE, not disk -- has no handler.  A node that
// physically executed the upgrade still has data/upgrade-info.json, which the dynamic
// registration picks up.  A node that STATE-SYNCED past the upgrade has the chain-state record
// and NO disk file; this list is the only thing that lets it start.
var historicalUpgradeNames = []string{
	"v1.1.23", // applied 2026-08-26; first plan ever executed on a qadena chain
}

// upgradeHandlerNames computes the deduped set of plan names this binary must register.  Pure so
// it is testable without constructing an app -- the four sources and why each exists are on
// RegisterUpgradeHandlers below.
func upgradeHandlerNames(binaryVersion string, historical []string, diskName string) []string {
	names := map[string]bool{UpgradeName: true}
	if binaryVersion != "" {
		names["v"+binaryVersion] = true
	}
	for _, n := range historical {
		if n != "" {
			names[n] = true
		}
	}
	if diskName != "" {
		names[diskName] = true
	}
	out := make([]string, 0, len(names))
	for n := range names {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// RegisterUpgradeHandlers wires x/upgrade for the cosmovisor flow.
//
// THE MECHANISM IS HANDLER ASYMMETRY.  A governance plan named "v<version>" halts every binary
// that does NOT register that name -- x/upgrade dumps data/upgrade-info.json and panics
// `UPGRADE "<name>" NEEDED`, the exact string cosmovisor watches for -- and is applied by the
// binary that DOES.  Because every build embeds its own version below, a binary automatically
// registers its own plan name: the version bump that already happens per release IS the handler
// registration, and the old binary halting at H is not a failure but the signal for the swap.
//
// Registered names, deduped:
//  1. the legacy v050-to-v053, whose store-loader block must stay pinned to it alone
//  2. "v" + this binary's embedded version (ldflags from cmd/qadenad/version.txt; a plain
//     `go build` without them leaves it empty -- warn rather than register a plan named "v")
//  3. whatever data/upgrade-info.json names -- the plan this node most recently halted for or
//     applied, so a restarted node always recognises its own history
//  4. historicalUpgradeNames above, for state-synced nodes with no disk file
//
// All version-named plans exist to move BINARIES at a height, not to add store modules.  A plan
// that genuinely adds one gets its own explicit handler and StoreUpgrades entry beside the legacy
// one -- do not widen the generic path.
func (app *App) RegisterUpgradeHandlers() {
	migrate := func(ctx context.Context, _ upgradetypes.Plan, fromVM module.VersionMap) (module.VersionMap, error) {
		// A BINARY-SWAP PLAN MUST NEVER *INITIALISE* A MODULE.  RunMigrations treats any module
		// missing from fromVM as brand new and runs its InitGenesis -- and on 2026-08-26 that
		// took the node down at the upgrade height with
		//
		//     panic: error initializing evm coin info: denom metadata aatom could not be found
		//
		// because x/vm, x/erc20 and the two ibc light clients were absent from this chain's
		// stored version map.  Every node applies the plan in the same block, so an InitGenesis
		// that panics on one panics on all of them -- and the block cannot be skipped, so the
		// chain is stuck until a new binary is staged everywhere.  A worse variant is silent: an
		// InitGenesis that SUCCEEDS re-initialises that module's state mid-chain.
		//
		// Filling the gaps with the CURRENT consensus versions means RunMigrations sees no new
		// modules, while still migrating every module whose STORED version is genuinely behind.
		vm := app.ModuleManager.GetVersionMap()
		for name, v := range fromVM {
			vm[name] = v
		}
		return app.ModuleManager.RunMigrations(ctx, app.Configurator(), vm)
	}

	upgradeInfo, err := app.UpgradeKeeper.ReadUpgradeInfoFromDisk()
	if err != nil {
		panic(err)
	}

	if cosmossdkversion.Version == "" {
		c.LoggerError(app.Logger(), "no embedded version (built without buildscripts/build.sh's ldflags?) -- "+
			"this binary registers no version-named upgrade handler and will HALT at any version-named "+
			"upgrade height rather than apply it")
	}
	for _, n := range upgradeHandlerNames(cosmossdkversion.Version, historicalUpgradeNames, upgradeInfo.Name) {
		app.UpgradeKeeper.SetUpgradeHandler(n, migrate)
	}

	// UNCHANGED, and pinned to the legacy name only: version-named plans add no store modules.
	if upgradeInfo.Name == UpgradeName && !app.UpgradeKeeper.IsSkipHeight(upgradeInfo.Height) {
		storeUpgrades := storetypes.StoreUpgrades{
			Added: []string{
				epochstypes.ModuleName,       // if not adding x/epochs to your chain, remove this line.
				protocolpooltypes.ModuleName, // if not adding x/protocolpool to your chain, remove this line.
			},
		}

		// configure store loader that checks if version == upgradeHeight and applies store upgrades
		app.SetStoreLoader(upgradetypes.UpgradeStoreLoader(upgradeInfo.Height, &storeUpgrades))
	}
}

func newPostHandler(app *App) (sdk.PostHandler, error) {
	postHandler, err := post.NewPostHandler(
		post.HandlerOptions{
			QadenaKeeper: &app.QadenaKeeper,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create post handler: %w", err)
	}

	return postHandler, nil
}

// New returns a reference to an initialized App.
func New(
	logger log.Logger,
	db dbm.DB,
	traceStore io.Writer,
	loadLatest bool,
	appOpts servertypes.AppOptions,
	wasmOpts []wasmkeeper.Option,
	baseAppOptions ...func(*baseapp.BaseApp),
) (*App, error) {
	var (
		app        = &App{}
		appBuilder *runtime.AppBuilder

		// merge the AppConfig and other configuration in one config
		appConfig = depinject.Configs(
			AppConfig(),
			depinject.Supply(
				// Supply the application options
				appOpts,
				// Supply with IBC keeper getter for the IBC modules with App Wiring.
				// The IBC Keeper cannot be passed because it has not been initiated yet.
				// Passing the getter, the app IBC Keeper will always be accessible.
				// This needs to be removed after IBC supports App Wiring.
				app.GetIBCKeeper,
				//				app.GetCapabilityScopedKeeper,
				// Supply the logger
				logger,

				// ADVANCED CONFIGURATION
				//
				// AUTH
				//
				// For providing a custom function required in auth to generate custom account types
				// add it below. By default the auth module uses simulation.RandomGenesisAccounts.
				//
				// authtypes.RandomGenesisAccountsFn(simulation.RandomGenesisAccounts),
				//
				// For providing a custom a base account type add it below.
				// By default the auth module uses authtypes.ProtoBaseAccount().
				//
				// func() sdk.AccountI { return authtypes.ProtoBaseAccount() },
				//
				// For providing a different address codec, add it below.
				// By default the auth module uses a Bech32 address codec,
				// with the prefix defined in the auth module configuration.
				//
				// func() address.Codec { return <- custom address codec type -> }

				//
				// STAKING
				//
				// For provinding a different validator and consensus address codec, add it below.
				// By default the staking module uses the bech32 prefix provided in the auth config,
				// and appends "valoper" and "valcons" for validator and consensus addresses respectively.
				// When providing a custom address codec in auth, custom address codecs must be provided here as well.
				//
				// func() runtime.ValidatorAddressCodec { return <- custom validator address codec type -> }
				// func() runtime.ConsensusAddressCodec { return <- custom consensus address codec type -> }

				//
				// MINT
				//

				// For providing a custom inflation function for x/mint add here your
				// custom function that implements the minttypes.InflationCalculationFn
				// interface.
			),
		)
	)

	if err := depinject.Inject(appConfig,
		&appBuilder,
		&app.appCodec,
		&app.legacyAmino,
		&app.txConfig,
		&app.interfaceRegistry,
		&app.AccountKeeper,
		&app.BankKeeper,
		&app.StakingKeeper,
		&app.DistrKeeper,
		&app.ConsensusParamsKeeper,
		&app.SlashingKeeper,
		&app.MintKeeper,
		&app.GovKeeper,
		&app.UpgradeKeeper,
		&app.ParamsKeeper,
		&app.AuthzKeeper,
		&app.EvidenceKeeper,
		&app.FeeGrantKeeper,
		&app.NFTKeeper,
		&app.GroupKeeper,
		&app.CircuitBreakerKeeper,
		&app.QadenaKeeper,
		&app.NameserviceKeeper,
		&app.PricefeedKeeper,
		&app.DsvsKeeper,
		&app.ProtocolPoolKeeper, // sdk 53.5
		&app.EpochsKeeper,       // sdk 53.5
		// this line is used by starport scaffolding # stargate/app/keeperDefinition
	); err != nil {
		panic(err)
	}

	// qadena
	c.LoggerInfo(logger, "Starting qadena node", cosmossdkversion.Version)

	evmcryptocodec.RegisterInterfaces(app.interfaceRegistry)
	evmeip712.RegisterInterfaces(app.interfaceRegistry)

	app.QadenaKeeper.LoadNodeParams(DefaultNodeHome)
	//	app.App.BaseApp.SetQadenaKeeper(app.QadenaKeeper)

	// Below we could construct and set an application specific mempool and
	// ABCI 1.0 PrepareProposal and ProcessProposal handlers. These defaults are
	// already set in the SDK's BaseApp, this shows an example of how to override
	// them.
	//
	// Example:
	//
	// app.App = appBuilder.Build(...)
	// nonceMempool := mempool.NewSenderNonceMempool()
	// abciPropHandler := NewDefaultProposalHandler(nonceMempool, app.App.BaseApp)
	//
	// app.App.BaseApp.SetMempool(nonceMempool)
	// app.App.BaseApp.SetPrepareProposal(abciPropHandler.PrepareProposalHandler())
	// app.App.BaseApp.SetProcessProposal(abciPropHandler.ProcessProposalHandler())
	//
	// Alternatively, you can construct BaseApp options, append those to
	// baseAppOptions and pass them to the appBuilder.
	//
	// Example:
	//
	// prepareOpt = func(app *baseapp.BaseApp) {
	// 	abciPropHandler := baseapp.NewDefaultProposalHandler(nonceMempool, app)
	// 	app.SetPrepareProposal(abciPropHandler.PrepareProposalHandler())
	// }
	// baseAppOptions = append(baseAppOptions, prepareOpt)
	//
	// create and set vote extension handler
	// voteExtOp := func(bApp *baseapp.BaseApp) {
	// 	voteExtHandler := NewVoteExtensionHandler()
	// 	voteExtHandler.SetHandlers(bApp)
	// }

	app.App = appBuilder.Build(db, traceStore, baseAppOptions...)

	// Replace bank keeper's blocked addresses with full set (module accounts + EVM precompiles)
	blockedAddrs := app.BankKeeper.GetBlockedAddresses()
	for k := range blockedAddrs {
		delete(blockedAddrs, k)
	}
	for addr := range BlockedAddresses() {
		blockedAddrs[addr] = true
	}

	// Every account-to-account movement of value goes through the AML scan, whichever module moves
	// it.  Without this the scan only covers MsgTransferFunds and `tx bank send` is an unmeasured
	// second route around it -- including around the eKYC gate, so a wallet refused a transfer for
	// having no residency could send the same funds anyway.
	app.BankKeeper.AppendSendRestriction(app.qadenaBankSendRestriction())

	/*
		newBlockedAddrs := app.BankKeeper.GetBlockedAddresses()
		for addr := range newBlockedAddrs {
			// log it
			app.Logger().Info("blocked address", "address", addr)
		}
	*/

	// Register non-dependency-inject modules
	if err := app.registerNonDependencyInjectModules(appOpts, wasmOpts); err != nil {
		return nil, err
	}

	// register streaming services
	if err := app.RegisterStreamingServices(appOpts, app.kvStoreKeys()); err != nil {
		return nil, err
	}

	/****  Module Options ****/

	// create the simulation manager and define the order of the modules for deterministic simulations
	//
	// NOTE: this is not required apps that don't use the simulator for fuzz testing transactions
	overrideModules := map[string]module.AppModuleSimulation{
		authtypes.ModuleName: auth.NewAppModule(app.appCodec, app.AccountKeeper, authsims.RandomGenesisAccounts, app.GetSubspace(authtypes.ModuleName)),
	}
	app.sm = module.NewSimulationManagerFromAppModules(app.ModuleManager.Modules, overrideModules)
	app.sm.RegisterStoreDecoders()

	// A custom InitChainer can be set if extra pre-init-genesis logic is required.
	// By default, when using app wiring enabled module, this is not required.
	// For instance, the upgrade module will set automatically the module version map in its init genesis thanks to app wiring.
	// However, when registering a module manually (i.e. that does not support app wiring), the module version map
	// must be set manually as follow. The upgrade module will de-duplicate the module version map.
	//
	// app.SetInitChainer(func(ctx sdk.Context, req *abci.RequestInitChain) (*abci.ResponseInitChain, error) {
	// 	app.UpgradeKeeper.SetModuleVersionMap(ctx, app.ModuleManager.GetVersionMap())
	// 	return app.App.InitChainer(ctx, req)
	// })

	app.RegisterUpgradeHandlers()

	// Captured here rather than looked up later: OfferSnapshot runs before the node has any chain
	// state, so the peers it can ask about enclave-private availability are exactly the ones the
	// operator configured to state-sync from.
	app.stateSyncRPCServers = parseStateSyncRPCServers(cast.ToString(appOpts.Get("statesync.rpc_servers")))

	maxGasWanted := cast.ToUint64(appOpts.Get(evmsrvflags.EVMMaxTxGasWanted))

	app.evmSetAnteHandler(app.txConfig, maxGasWanted)

	// set the EVM priority nonce mempool
	// if you wish to use the noop mempool, remove this codeblock
	if err := app.configureEVMMempool(appOpts, logger); err != nil {
		panic(fmt.Sprintf("failed to configure EVM mempool: %s", err.Error()))
	}

	// must be before Loading version
	// requires the snapshot store to be created and registered as a BaseAppOption
	// see cmd/wasmd/root.go: 206 - 214 approx
	if manager := app.SnapshotManager(); manager != nil {
		err := manager.RegisterExtensions(
			wasmkeeper.NewWasmSnapshotter(app.CommitMultiStore(), &app.WasmKeeper),
		)
		if err != nil {
			panic(fmt.Errorf("failed to register snapshot extension: %s", err))
		}
	}

	postHandler, err := newPostHandler(app)
	if err != nil {
		panic(err)
	}
	app.SetPostHandler(postHandler)

	// Hand the supervisor the values a spawn needs (home, pruning, log level), derived from the
	// same appOpts the chain itself runs on.  Whether InitEnclave then spawns at all is decided
	// per command (start and rollback opt in; everything else dials an external enclave, as
	// before) -- see x/qadena/keeper/enclave_supervisor.go.
	qadenamodulekeeper.ConfigureEnclaveSupervisor(logger, appOpts)
	if !app.QadenaKeeper.InitEnclave() {
		panic("Unable to connect to enclave")
	}

	if err := app.Load(loadLatest); err != nil {
		return nil, err
	}

	if loadLatest {
		// BEFORE anything reads state.  A store that restored without its fast index reads as empty
		// while hashing correctly, so every later step -- including the pinned-code load below --
		// would run against silently missing data and succeed.  See assertStoresAreReadable.
		if err := app.assertStoresAreReadable(); err != nil {
			panic(err)
		}

		ctx := app.BaseApp.NewUncachedContext(true, tmproto.Header{})

		// Initialize pinned codes in wasmvm as they are not persisted there
		if err := app.WasmKeeper.InitializePinnedCodes(ctx); err != nil {
			panic(fmt.Sprintf("failed initialize pinned codes %s", err))
		}
	}

	return app, nil
}

// Commit shadows BaseApp.Commit to add the second phase of the chain<->enclave two-phase commit.
//
// Dispatch: CometBFT calls the app through server.NewCometABCIWrapper(app), which stores the
// servertypes.ABCI INTERFACE whose dynamic type is *App -- so this method, not the promoted
// BaseApp.Commit, is what consensus invokes.
//
// The enclave's own durable commit (the PREPARE) happened during EndBlock.  Once BaseApp.Commit
// returns, the block is durable on the chain side too, and ConfirmHeight advances the enclave's
// confirmed watermark to match.  The window between those two commits is precisely the crash
// window that used to be unrepairable: comet's handshake sees appHeight == storeHeight and will
// NOT replay the block, so without an explicit confirm/rollback protocol the enclave's extra
// state was a permanent, invisible divergence.  With the watermarks, startup reconciliation
// (EnclaveBeginBlock) detects prepared > confirmed == chain and rolls the enclave back one
// height automatically.
//
// This runs AFTER consensus execution, so nothing here touches block state or the app hash --
// a node-local watermark only.  On persistent failure the node halts: producing further blocks
// with an unconfirmable enclave re-opens the divergence this exists to close.
func (app *App) Commit() (*abci.ResponseCommit, error) {
	res, err := app.BaseApp.Commit()
	if err != nil {
		return res, err
	}

	height := app.BaseApp.LastBlockHeight()
	var cerr error
	for attempt := 1; attempt <= 3; attempt++ {
		if cerr = app.QadenaKeeper.EnclaveConfirmHeight(height); cerr == nil {
			return res, nil
		}
		if status.Code(cerr) == codes.Unimplemented {
			// an old enclave binary against a new chain binary; retrying cannot help
			panic("qadena: the running enclave does not implement ConfirmHeight -- qadenad and qadenad_enclave must be upgraded together: " + cerr.Error())
		}
		time.Sleep(time.Duration(attempt) * time.Second)
	}
	// The block IS committed; only the enclave's watermark is behind.  That exact state is what
	// startup reconciliation repairs (case B: confirm the prepared height) -- so halting here is
	// safe, and continuing is not.
	//
	// ANNOUNCED, because this is a halt the watchdog has to be able to SEE.  It is deliberately not
	// haltOnEnclaveFailure -- that one is EndBlock-scoped and exists to stop a fork in the app hash,
	// and neither property holds here -- but it halts for the same cancellation, and the watchdog
	// classifies on the bit alone.  Without this it reports "the calls returned but NOTHING HALTED
	// FOR THEM" and blames a call site that is behaving correctly (2026-08-31, M1, height 11059).
	// It also swaps the bare "context canceled" for the watchdog's recorded cause, so the panic says
	// the enclave went silent rather than merely that a context ended.
	cerr = qadenamodulekeeper.AnnounceEnclaveHalt(cerr)
	panic("qadena: enclave ConfirmHeight failed after the chain committed height " +
		fmt.Sprintf("%d", height) + ": " + cerr.Error() +
		" -- halting; on restart, reconciliation confirms or rolls back as needed")
}

// parseStateSyncRPCServers splits config.toml's comma-separated statesync.rpc_servers.
func parseStateSyncRPCServers(raw string) []string {
	var out []string
	for _, s := range strings.Split(raw, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// OfferSnapshot shadows BaseApp.OfferSnapshot to refuse a chain snapshot this node's enclave could
// never be seeded for.
//
// Dispatch is the same trick Commit uses above: CometBFT holds the servertypes.ABCI interface whose
// dynamic type is *App, so this method rather than the promoted BaseApp one is what consensus calls.
//
// A chain snapshot carries chain stores only.  Accepting one at a height no peer can serve
// enclave-private state for means downloading it, restoring it, and only then discovering at the
// first BeginBlock that the private tables cannot be fetched -- at which point the node halts and
// an operator has to intervene.  Rejecting here costs one round trip and lets CometBFT try the next
// snapshot it was offered, which may well be at a servable height.
//
// REJECT, deliberately, not ABORT: ABORT tears down snapshot restoration entirely, and "this
// particular height does not work" is not a reason to give up on all of them.
func (app *App) OfferSnapshot(req *abci.RequestOfferSnapshot) (*abci.ResponseOfferSnapshot, error) {
	if req == nil || req.Snapshot == nil {
		return app.BaseApp.OfferSnapshot(req)
	}
	height := int64(req.Snapshot.Height)

	// No peers configured means state-sync is not in use and this should not have been called;
	// defer rather than invent a verdict.
	if len(app.stateSyncRPCServers) == 0 {
		return app.BaseApp.OfferSnapshot(req)
	}

	servable, reason := app.enclavePrivateStateServable(height)
	if !servable {
		app.Logger().Error("rejecting chain snapshot: no peer's enclave can supply private state at that height",
			"height", height, "reason", reason,
			"note", "the enclave-private tables (AML window, credential uniqueness index, sub-wallet maps) are not in a chain snapshot and cannot be rebuilt from chain data")
		return &abci.ResponseOfferSnapshot{Result: abci.ResponseOfferSnapshot_REJECT}, nil
	}

	return app.BaseApp.OfferSnapshot(req)
}

// enclavePrivateStateServable asks the configured state-sync peers whether any of them can serve
// enclave-private state at the given height.
//
// Unauthenticated on purpose.  It carries no secrets, and a peer that lies costs only a wasted
// attempt: the transfer itself is attested and fails closed, so this is a liveness hint rather than
// a security boundary.
func (app *App) enclavePrivateStateServable(height int64) (bool, string) {
	lastReason := "no peer answered"
	for _, peer := range app.stateSyncRPCServers {
		node := peer
		if !strings.Contains(node, "://") {
			node = "tcp://" + node
		}
		clientCtx := app.clientCtx.WithNodeURI(node)
		rpcClient, err := client.NewClientFromNode(node)
		if err != nil {
			lastReason = fmt.Sprintf("%s: %v", peer, err)
			continue
		}
		clientCtx = clientCtx.WithClient(rpcClient)

		res, err := qadenatypes.NewQueryClient(clientCtx).EnclavePrivateStateAvailability(
			context.Background(), &qadenatypes.QueryEnclavePrivateStateAvailabilityRequest{})
		if err != nil {
			lastReason = fmt.Sprintf("%s: %v", peer, err)
			continue
		}

		// A peer can serve any height it still has indexed, which -- because the enclave commits
		// every block while the chain snapshots every few thousand -- is very nearly always a
		// superset of the heights the chain can offer.
		if res.EarliestHeight <= height && height <= res.PreparedHeight {
			return true, ""
		}
		lastReason = fmt.Sprintf("%s serves heights %d..%d", peer, res.EarliestHeight, res.PreparedHeight)
	}
	return false, lastReason
}

// LegacyAmino returns App's amino codec.
//
// NOTE: This is solely to be used for testing purposes as it may be desirable
// for modules to register their own custom testing types.
func (app *App) LegacyAmino() *codec.LegacyAmino {
	return app.legacyAmino
}

// AppCodec returns App's app codec.
//
// NOTE: This is solely to be used for testing purposes as it may be desirable
// for modules to register their own custom testing types.
func (app *App) AppCodec() codec.Codec {
	return app.appCodec
}

// GetKey returns the KVStoreKey for the provided store key.
func (app *App) GetKey(storeKey string) *storetypes.KVStoreKey {
	kvStoreKey, ok := app.UnsafeFindStoreKey(storeKey).(*storetypes.KVStoreKey)
	if !ok {
		return nil
	}
	return kvStoreKey
}

// GetMemKey returns the MemoryStoreKey for the provided store key.
func (app *App) GetMemKey(storeKey string) *storetypes.MemoryStoreKey {
	key, ok := app.UnsafeFindStoreKey(storeKey).(*storetypes.MemoryStoreKey)
	if !ok {
		return nil
	}

	return key
}

// kvStoreKeys returns all the kv store keys registered inside App.
func (app *App) kvStoreKeys() map[string]*storetypes.KVStoreKey {
	keys := make(map[string]*storetypes.KVStoreKey)
	for _, k := range app.GetStoreKeys() {
		if kv, ok := k.(*storetypes.KVStoreKey); ok {
			keys[kv.Name()] = kv
		}
	}

	return keys
}

// GetSubspace returns a param subspace for a given module name.
func (app *App) GetSubspace(moduleName string) paramstypes.Subspace {
	subspace, _ := app.ParamsKeeper.GetSubspace(moduleName)
	return subspace
}

// GetIBCKeeper returns the IBC keeper.
func (app *App) GetIBCKeeper() *ibckeeper.Keeper {
	return app.IBCKeeper
}

/*
// GetCapabilityScopedKeeper returns the capability scoped keeper.
func (app *App) GetCapabilityScopedKeeper(moduleName string) capabilitykeeper.ScopedKeeper {
	return app.CapabilityKeeper.ScopeToModule(moduleName)
}
*/

// SimulationManager implements the SimulationApp interface.
func (app *App) SimulationManager() *module.SimulationManager {
	return app.sm
}

// RegisterAPIRoutes registers all application module routes with the provided
// API server.
func (app *App) RegisterAPIRoutes(apiSvr *api.Server, apiConfig config.APIConfig) {
	app.App.RegisterAPIRoutes(apiSvr, apiConfig)
	// register swagger API in app.go so that other applications can override easily
	if err := server.RegisterSwaggerAPI(apiSvr.ClientCtx, apiSvr.Router, apiConfig.Swagger); err != nil {
		panic(err)
	}

	// register app's OpenAPI routes.
	docs.RegisterOpenAPIService(Name, apiSvr.Router)
}

// GetMaccPerms returns a copy of the module account permissions
//
// NOTE: This is solely to be used for testing purposes.
func GetMaccPerms() map[string][]string {
	dup := make(map[string][]string)
	for _, perms := range moduleAccPerms {
		dup[perms.Account] = perms.Permissions
	}
	return dup
}

// qadenaBankSendRestriction refuses any account-to-account transfer that has not been AML-scanned.
//
// Registered on the bank keeper, so it sits under SendCoins and per-output under InputOutputCoins.
// That means it covers MsgSend, MsgMultiSend, authz-wrapped sends and EVM value transfers alike,
// rather than only the message a user typed.
//
// Only two cases, and only one of them skips the scan:
//
//  1. a MODULE account on either side.  Fee collection, staking, governance deposits and the qadena
//     module's own transfer escrow all move coins this way, and none of them are one person paying
//     another.  Checked against a precomputed set, so the common case costs no store read.
//  2. everything else is SCANNED, and refused if the scan refuses.
//
// There used to be a third case between them: a whitelist of senders exempt from scanning, holding
// the funding treasuries.  It existed only because a report could not name a party without a
// personal-info credential, so an account that had none could not be scanned at all.  Reports now
// carry a party kind and a contract descriptor, so such an account CAN be scanned and reported --
// and the exemption, having lost its justification, is gone.  The treasuries moved to the
// scanned-contract whitelist, which permits them to take part without a credential while leaving
// every send they make measured and reportable.
//
// A send that cannot be scanned is refused rather than waved through: permitting it would leave
// open exactly the gap this exists to close.
func (app *App) qadenaBankSendRestriction() banktypes.SendRestrictionFn {
	moduleAddrs := make(map[string]bool)
	for acc := range GetMaccPerms() {
		moduleAddrs[authtypes.NewModuleAddress(acc).String()] = true
	}

	return func(ctx context.Context, fromAddr, toAddr sdk.AccAddress, amt sdk.Coins) (sdk.AccAddress, error) {
		if moduleAddrs[fromAddr.String()] || moduleAddrs[toAddr.String()] {
			return toAddr, nil
		}

		sdkctx := sdk.UnwrapSDKContext(ctx)

		if err := app.QadenaKeeper.ScanBankSend(sdkctx, fromAddr, toAddr, amt); err != nil {
			return toAddr, err
		}

		return toAddr, nil
	}
}

// wasmContractInfoSource lets x/qadena ask about wasm state without importing wasmd.
//
// The scanned-contract whitelist pins each entry to a code ID, and that pin has to be re-verified on
// every send -- otherwise migrating a whitelisted contract would carry its approval over to code
// governance never reviewed.  Answering "what code is this address running" needs wasmd's keeper,
// which lives here, so the dependency points this way rather than into the module.
type wasmContractInfoSource struct {
	wasm *wasmkeeper.Keeper
}

func (s wasmContractInfoSource) ContractCodeID(ctx sdk.Context, addr sdk.AccAddress) (uint64, bool) {
	info := s.wasm.GetContractInfo(ctx, addr)
	if info == nil {
		return 0, false
	}
	return info.CodeID, true
}

// BlockedAddresses returns all the app's blocked account addresses.
//
// Note, this includes:
//   - module accounts
//   - Ethereum's native precompiled smart contracts
//   - Cosmos EVM's available static precompiled contracts
func BlockedAddresses() map[string]bool {
	blockedAddrs := make(map[string]bool)

	maccPerms := GetMaccPerms()
	accs := make([]string, 0, len(maccPerms))
	for acc := range maccPerms {
		accs = append(accs, acc)
	}
	sort.Strings(accs)

	for _, acc := range accs {
		blockedAddrs[authtypes.NewModuleAddress(acc).String()] = true
	}

	blockedPrecompilesHex := evmtypes.AvailableStaticPrecompiles
	for _, addr := range corevm.PrecompiledAddressesPrague {
		blockedPrecompilesHex = append(blockedPrecompilesHex, addr.Hex())
	}

	for _, precompile := range blockedPrecompilesHex {
		blockedAddrs[evmutils.Bech32StringFromHexAddress(precompile)] = true
	}

	return blockedAddrs
}

func (app *App) evmSetAnteHandler(txConfig client.TxConfig, maxGasWanted uint64) {
	options := evmante.HandlerOptions{
		Cdc:                    app.appCodec,
		AccountKeeper:          app.AccountKeeper,
		BankKeeper:             app.BankKeeper,
		ExtensionOptionChecker: evmantetypes.HasDynamicFeeExtensionOption,
		EvmKeeper:              app.EVMKeeper,
		FeegrantKeeper:         app.FeeGrantKeeper,
		IBCKeeper:              app.IBCKeeper,
		FeeMarketKeeper:        app.FeeMarketKeeper,
		SignModeHandler:        txConfig.SignModeHandler(),
		SigGasConsumer:         evmante.SigVerificationGasConsumer,
		MaxTxGasWanted:         maxGasWanted,
		DynamicFeeChecker:      true,
		PendingTxListener:      app.onPendingTx,
	}
	if err := options.Validate(); err != nil {
		panic(err)
	}

	app.SetAnteHandler(evmante.NewAnteHandler(options))
}

func (app *App) onPendingTx(hash evmcommon.Hash) {
	for _, listener := range app.EVMPendingTxListeners {
		listener(hash)
	}
}

// RegisterPendingTxListener is used by json-rpc server to listen to pending transactions callback.
func (app *App) RegisterPendingTxListener(listener func(evmcommon.Hash)) {
	app.EVMPendingTxListeners = append(app.EVMPendingTxListeners, listener)
}

func (app *App) GetAnteHandler() sdk.AnteHandler {
	return app.BaseApp.AnteHandler()
}

func (app *App) SetClientCtx(clientCtx client.Context) { // TODO:VLAD - Remove this if possible
	app.clientCtx = clientCtx

}

// Close unsubscribes from the CometBFT event bus (if set) and closes the mempool and underlying BaseApp.
func (app *App) Close() error {
	var err error

	if app.EVMMempool != nil {
		app.Logger().Info("Shutting down mempool")
		err = app.EVMMempool.Close()
	}

	msg := "Application gracefully shutdown"
	err = errors.Join(err, app.BaseApp.Close())
	if err == nil {
		app.Logger().Info(msg)
	} else {
		app.Logger().Error(msg, "error", err)
	}

	return err
}

func (app *App) GetMempool() sdkmempool.ExtMempool {
	return app.EVMMempool
}
