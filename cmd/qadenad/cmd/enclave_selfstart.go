package cmd

// Wiring for the self-starting enclave: the start command opts into spawning, and arms the
// BeginBlock-anchored init dispatch with everything the deleted init_enclave.sh derived by hand
// -- the moniker, the external address out of config.toml, the jar/regulator ids, the ego
// measurements, and the pioneer key out of the node's own keyring.
//
// Kept in package cmd (not keeper) because this is the one place that has a client context: the
// keyring backend comes from client.toml exactly as it did for the CLI, and the keeper must not
// grow CLI plumbing.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"cosmossdk.io/log"
	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/server"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"
	"github.com/c3qtech/qadena_v3/x/qadena/keeper"
	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

const (
	flagExternalEnclave    = "external-enclave"
	flagEnclaveJarID       = "enclave-jar-id"
	flagEnclaveRegulatorID = "enclave-regulator-id"

	// Only used in-process, in the enclave; does not affect security.  Same value the CLI and
	// the enclave itself use (cmd/qadenad/enclave_cmd.go, cmd/qadenad_enclave/enclave.go).
	initEnclaveArmorPassPhrase = "8675309"
)

// addEnclaveSelfStartFlags registers the self-start flags on the start command and chains a
// PreRunE that enables spawning and arms the init dispatch.  Called from addModuleInitFlags,
// which evmserver invokes with the start command only.
func addEnclaveSelfStartFlags(startCmd *cobra.Command) {
	startCmd.Flags().Bool(flagExternalEnclave, false, "do not spawn the enclave processes; dial an externally started enclave (debugger workflow: run_enclave_standalone.sh)")
	startCmd.Flags().String(flagEnclaveJarID, "jar1", "jar id used when this node initializes a fresh chain's enclave")
	startCmd.Flags().String(flagEnclaveRegulatorID, "regulator1", "regulator id used when this node initializes a fresh chain's enclave")

	prev := startCmd.PreRunE
	startCmd.PreRunE = func(cmd *cobra.Command, args []string) error {
		if prev != nil {
			if err := prev(cmd, args); err != nil {
				return err
			}
		}
		return wireEnclaveSelfStart(cmd)
	}
}

func wireEnclaveSelfStart(cmd *cobra.Command) error {
	// Start mode always: --external-enclave withholds only the CHAIN enclave, never the signer
	// (this node's remote block signer -- see SetExternalChainEnclave).
	external, _ := cmd.Flags().GetBool(flagExternalEnclave)
	keeper.EnableEnclaveSpawn(keeper.SpawnModeStart)
	keeper.SetExternalChainEnclave(external)

	serverCtx := server.GetServerContextFromCmd(cmd)
	cfg := serverCtx.Config
	moniker := cfg.Moniker
	home := cfg.RootDir

	// Qadena's own debug-log gate (c.LogLevelDebugEnabled) is set from the --log-level FLAG in
	// root.go and from nowhere else -- the deleted run.sh passed the flag explicitly on every
	// start, derived from config.toml.  With the flag gone from the start line, derive it from
	// the same config here, or every chain-side ContextDebug/LoggerDebug line (per-block
	// accumulator agreement included) silently disappears.  An explicit flag still wins.
	if level, err := cmd.Flags().GetString("log-level"); err != nil || level == "" {
		c.SetLogLevel(cfg.LogLevel)
	}

	// The fail-fast run.sh had: a node with no external_address cannot register itself.  Checked
	// here, at start, rather than at dispatch time three blocks in.
	extAddr := externalAddressHost(cfg.P2P.ExternalAddress)
	if extAddr == "" {
		return fmt.Errorf("config.toml's p2p.external_address is not set -- the enclave cannot register this pioneer without it; run init.sh or set it by hand")
	}

	jarID, _ := cmd.Flags().GetString(flagEnclaveJarID)
	regulatorID, _ := cmd.Flags().GetString(flagEnclaveRegulatorID)

	keeper.ArmInitEnclaveDispatch(jarID, func() error {
		return runInitEnclaveDispatch(cmd, serverCtx.Logger, moniker, extAddr, jarID, regulatorID, home)
	})
	return nil
}

// externalAddressHost extracts the bare host the way get_external_address.sh did: the value of
// p2p.external_address ("1.2.3.4:26656", possibly with a scheme) reduced to its host part.
func externalAddressHost(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "tcp://")
	if i := strings.Index(v, ":"); i >= 0 {
		v = v[:i]
	}
	return v
}

// runInitEnclaveDispatch is what the deleted init_enclave.sh did, with the same inputs derived
// in-process.  It runs in a goroutine off BeginBlock (see keeper.MaybeDispatchInitEnclave), on a
// node whose RPC is serving -- the enclave answers by broadcasting its registration tx to it.
func runInitEnclaveDispatch(cmd *cobra.Command, logger log.Logger, moniker, extAddr, jarID, regulatorID, home string) error {
	if keeper.EnclaveGRPCClient == nil {
		return errors.New("enclave client not initialized")
	}

	// Real mode wants the actual measurements; debug wants the "*" wildcard the debug identity
	// rows carry.  Judged the same way the supervisor judges the spawn.
	signerID, uniqueID := "*", "*"
	if keeper.EnclaveRealMode(home) {
		var err error
		if signerID, err = keeper.EgoID("signerid", home+"/config/public.pem"); err != nil {
			return fmt.Errorf("cannot read the signer id (reinstall public.pem: install_release.sh, or copy from cmd/qadenad_enclave): %w", err)
		}
		if uniqueID, err = keeper.EgoID("uniqueid", home+"/bin/qadenad_enclave"); err != nil {
			return fmt.Errorf("cannot read the enclave's unique id: %w", err)
		}
	}

	// The pioneer key out of the node's own keyring, exactly as the CLI did (backend from
	// client.toml).  The armored export travels to the enclave, which imports it in-memory.
	clientCtx, err := client.GetClientTxContext(cmd)
	if err != nil {
		return fmt.Errorf("cannot build a client context for the keyring: %w", err)
	}
	_, _, _, _, armorPrivK, err := c.GetAddressByName(clientCtx, moniker, initEnclaveArmorPassPhrase)
	if err != nil {
		return fmt.Errorf("no key named %q (the moniker) in the keyring: %w", moniker, err)
	}

	msg := types.MsgInitEnclave{
		PioneerID:              moniker,
		ExternalAddress:        extAddr,
		JarID:                  jarID,
		RegulatorID:            regulatorID,
		PioneerArmorPrivK:      armorPrivK,
		PioneerArmorPassPhrase: initEnclaveArmorPassPhrase,
		SignerID:               signerID,
		UniqueID:               uniqueID,
	}

	// Generous: the enclave generates keys, builds remote reports and broadcasts a tx (sync,
	// i.e. through CheckTx) before answering.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	r, err := keeper.EnclaveGRPCClient.InitEnclave(ctx, &msg)
	if err != nil {
		return err
	}
	if !r.Status {
		return errors.New("the enclave reported InitEnclave failure")
	}
	return nil
}
