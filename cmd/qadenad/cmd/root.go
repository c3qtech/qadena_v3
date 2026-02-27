package cmd

import (
	"os"
	"strings"

	"cosmossdk.io/client/v2/autocli"
	clientv2keyring "cosmossdk.io/client/v2/autocli/keyring"
	"cosmossdk.io/core/address"
	"cosmossdk.io/depinject"
	"cosmossdk.io/log"
	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/config"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"

	//	"github.com/cosmos/cosmos-sdk/runtime"
	"github.com/cosmos/cosmos-sdk/server"

	//	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/module"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	"github.com/cosmos/cosmos-sdk/x/auth/tx"
	txmodule "github.com/cosmos/cosmos-sdk/x/auth/tx/config"
	"github.com/cosmos/cosmos-sdk/x/auth/types"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/c3qtech/qadena_v3/app"
	cmdcfg "github.com/c3qtech/qadena_v3/cmd/config"
	c "github.com/c3qtech/qadena_v3/x/qadena/common"

	//	txsigning "cosmossdk.io/x/tx/signing"

	//	qadenakr "github.com/c3qtech/qadena_v3/crypto/keyring"
	evmcryptocodec "github.com/cosmos/evm/crypto/codec"
	evmeip712 "github.com/cosmos/evm/ethereum/eip712"

	evmhd "github.com/cosmos/evm/crypto/hd"
	//	"github.com/cosmos/gogoproto/proto"
	enccodec "github.com/cosmos/cosmos-sdk/std"
	//
	// evmaddress "github.com/cosmos/evm/encoding/address"
	//
	//	evmerc20types "github.com/cosmos/evm/x/erc20/types"
	//	evmtypes "github.com/cosmos/evm/x/vm/types"
)

// NewRootCmd creates a new root command for qadenad. It is called once in the main function.
func NewRootCmd() *cobra.Command {
	initSDKConfig()

	var (
		txConfigOpts       tx.ConfigOptions
		autoCliOpts        autocli.AppOptions
		moduleBasicManager module.BasicManager
		clientCtx          client.Context
	)

	if err := depinject.Inject(
		depinject.Configs(app.AppConfig(),
			depinject.Supply(
				log.NewNopLogger(),
			),
			depinject.Provide(
				ProvideClientContext,
				ProvideKeyring,
			),
		),
		&txConfigOpts,
		&autoCliOpts,
		&moduleBasicManager,
		&clientCtx,
	); err != nil {
		panic(err)
	}

	rootCmd := &cobra.Command{
		Use:           app.Name + "d",
		Short:         "Start qadena node",
		SilenceErrors: true,
		SilenceUsage:  true,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			// set the default command outputs
			cmd.SetOut(cmd.OutOrStdout())
			cmd.SetErr(cmd.ErrOrStderr())

			clientCtx = clientCtx.WithCmdContext(cmd.Context())
			clientCtx, err := client.ReadPersistentCommandFlags(clientCtx, cmd.Flags())
			if err != nil {
				return err
			}

			clientCtx, err = config.ReadFromClientConfig(clientCtx)
			if err != nil {
				return err
			}

			if level, err := cmd.Flags().GetString("log-level"); err == nil && level != "" {
				c.SetLogLevel(level)
			}

			// This needs to go after ReadFromClientConfig, as that function
			// sets the RPC client needed for SIGN_MODE_TEXTUAL.
			txConfigOpts.EnabledSignModes = append(txConfigOpts.EnabledSignModes, signing.SignMode_SIGN_MODE_TEXTUAL)
			txConfigOpts.TextualCoinMetadataQueryFn = txmodule.NewGRPCCoinMetadataQueryFn(clientCtx)
			txConfigWithTextual, err := tx.NewTxConfigWithOptions(
				codec.NewProtoCodec(clientCtx.InterfaceRegistry),
				txConfigOpts,
			)
			if err != nil {
				return err
			}

			clientCtx = clientCtx.WithTxConfig(txConfigWithTextual)
			if err := client.SetCmdClientContextHandler(clientCtx, cmd); err != nil {
				return err
			}

			customAppTemplate, customAppConfig := initAppConfig()
			customCMTConfig := initCometBFTConfig()

			return server.InterceptConfigsPreRunHandler(cmd, customAppTemplate, customAppConfig, customCMTConfig)
		},
	}

	rootCmd.PersistentFlags().String("log-level", "", "Log level override for qadenad (e.g. debug, info, error)")

	// Since the IBC modules don't support dependency injection, we need to
	// manually register the modules on the client side.
	// This needs to be removed after IBC supports App Wiring.
	nonDependencyInjectModules := app.RegisterNonDependencyInjectRegistryInterfaces(clientCtx.InterfaceRegistry)
	for name, mod := range nonDependencyInjectModules {
		moduleBasicManager[name] = module.CoreAppModuleBasicAdaptor(name, mod)
		autoCliOpts.Modules[name] = mod
	}

	initRootCmd(rootCmd, clientCtx.TxConfig, moduleBasicManager)

	overwriteFlagDefaults(rootCmd, map[string]string{
		flags.FlagChainID:        strings.ReplaceAll(app.Name, "-", ""),
		flags.FlagKeyringBackend: "test",
	})

	if cmdcfg.QadenaUsesEthSecP256k1 {
		overwriteFlagDefaults(rootCmd, map[string]string{
			flags.FlagKeyType: string(evmhd.EthSecp256k1.Name()),
		})
	}

	if err := autoCliOpts.EnhanceRootCommand(rootCmd); err != nil {
		panic(err)
	}

	return rootCmd
}

func overwriteFlagDefaults(c *cobra.Command, defaults map[string]string) {
	set := func(s *pflag.FlagSet, key, val string) {
		if f := s.Lookup(key); f != nil {
			f.DefValue = val
			_ = f.Value.Set(val)
		}
	}
	for key, val := range defaults {
		set(c.Flags(), key, val)
		set(c.PersistentFlags(), key, val)
	}
	for _, c := range c.Commands() {
		overwriteFlagDefaults(c, defaults)
	}
}

func ProvideClientContext(
	appCodec codec.Codec,
	interfaceRegistry codectypes.InterfaceRegistry,
	txConfig client.TxConfig,
	legacyAmino *codec.LegacyAmino,
) client.Context {

	if cmdcfg.QadenaUsesEthSecP256k1 {
		evmcryptocodec.RegisterInterfaces(interfaceRegistry)
		evmeip712.RegisterInterfaces(interfaceRegistry)
		legacyAmino = codec.NewLegacyAmino()
		evmcryptocodec.RegisterCrypto(legacyAmino)
	} else {
		enccodec.RegisterLegacyAminoCodec(legacyAmino)
	}

	clientCtx := client.Context{}.
		WithCodec(appCodec).
		WithInterfaceRegistry(interfaceRegistry).
		WithTxConfig(txConfig).
		WithLegacyAmino(legacyAmino).
		WithInput(os.Stdin).
		WithAccountRetriever(types.AccountRetriever{}).
		WithHomeDir(app.DefaultNodeHome).
		WithKeyringOptions(evmhd.EthSecp256k1Option()). // COSMOS EVM
		WithLedgerHasProtobuf(true).                    // COSMOS EVM
		WithViper(app.Name)                             // env variable prefix

	// Read the config again to overwrite the default values with the values from the config file
	clientCtx, _ = config.ReadFromClientConfig(clientCtx)

	return clientCtx
}

func ProvideKeyring(clientCtx client.Context, addressCodec address.Codec) (clientv2keyring.Keyring, error) {
	kb, err := client.NewKeyringFromBackend(clientCtx, clientCtx.Keyring.Backend())
	if err != nil {
		return nil, err
	}

	return keyring.NewAutoCLIKeyring(kb)
}
