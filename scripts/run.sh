#!/bin/zsh

# Runs a Qadena node.  Since the enclave-selfstart change this is a thin wrapper: `qadenad start`
# itself spawns and supervises both enclave processes (x/qadena/keeper/enclave_supervisor.go) and
# initializes a fresh chain's enclave from BeginBlock (enclave_init_dispatch.go).  What remains
# here is host-side preparation that the chain binary should not do:
#
#   - the SGX device / root preflight, loudly and BEFORE output disappears into rotatelogs
#   - the enclave-upgrade check (swaps binaries; must precede any process starting)
#   - the DCAP/PCCS attestation sidecar for real enclaves (managing docker is host provisioning)
#
# The five-script choreography this replaced -- run_enclave.sh, run_realenclave.sh,
# run_signerenclave.sh, run_realsignerenclave.sh, delayed_init_enclave.sh, init_enclave.sh, each
# started in strict order with poll loops between -- is gone.  The enclave death policy changed
# with it, deliberately: a spawned enclave that exits takes the node down with a named error
# instead of being silently respawned, so the process supervisor (systemd Restart=on-failure)
# restarts the node and the startup reconcile path recovers.  See the supervisor's file comment
# for why the respawn loops had to go.

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

# Root is needed only when we will actually run an ego enclave -- i.e. SGX hardware AND a signed
# binary.  qadenad re-checks this in its spawn preflight with the same remedies, but failing HERE
# keeps the message on the operator's terminal instead of inside the log pipe.
warn_if_sgx_binary_missing "run.sh" "$qadenabin/qadenad_enclave"
needs_root_if_real_enclave "run.sh" "$qadenabin/qadenad_enclave"

EXTERNAL_ENCLAVE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --external-enclave)
      # Forwarded to qadenad: dial an externally started enclave (run_enclave_standalone.sh,
      # typically under a debugger) instead of spawning one.
      EXTERNAL_ENCLAVE="--external-enclave"
      shift
      ;;
    --help)
      echo "run.sh:  Usage: run.sh [--external-enclave]"
      echo "run.sh:    --external-enclave   do not spawn enclaves; dial one started separately"
      echo "run.sh:                         (see run_enclave_standalone.sh)"
      exit 0
      ;;
    *)
      echo "run.sh:  Unknown option: $1"
      exit 1
      ;;
  esac
done

# Fail before anything starts: a node with no external_address cannot register itself, and
# qadenad start would refuse a few seconds later anyway -- this keeps the message here.
EXT_ADDR=`$qadenascripts/get_external_address.sh`
if [[ $EXT_ADDR == "" ]] ; then
    echo "run.sh:  Error, config.toml's external_address is not defined.  Try running init.sh"
    exit 1
fi

$qadenascripts/check_upgrade_enclave.sh
RET=$?
if [ $RET -ne 0 ] ; then
    echo "run.sh:  Error: qadenad_enclave has an upgrade, but it failed when trying to upgrade."
    if [ $RET -eq 5 ] ; then
        echo "run.sh:  Error: qadenad_enclave upgrade failed because the current enclave has not been registered with the chain.  Did you submit a proposal?"
        exit 5
    fi
    exit $RET
fi

# Attestation must be available before qadenad spawns a REAL enclave.  Skipped entirely for a
# debug build; skipped for --external-enclave because whoever started that enclave prepared it.
if [[ -z $EXTERNAL_ENCLAVE ]] && use_real_enclave "$qadenabin/qadenad_enclave" ; then
    $qadenascripts/ensure_sgx_attestation.sh || exit 1
fi

echo "run.sh: ------------"
echo "run.sh: START QADENA"
echo "run.sh: ------------"

# Foreground: qadenad is now the whole node -- it spawns the enclaves, and this script has
# nothing to monitor.  Note what is GONE from this line versus the old one: --enclave-addr and
# the id flags were inert (the unix-domain-socket branch never read them), and --log-level was a
# lossy re-derivation of the config.toml value qadenad reads natively.
#
# COSMOVISOR AUTO-DETECT.  A node whose disk carries the cosmovisor tree (cosmovisor_managed:
# the `current` symlink exists -- the one thing cosmovisor itself maintains) launches through
# cosmovisor with the SAME flags; everything else launches exactly as before.  The node's own
# disk state decides, so the ~30 scripts that start and stop nodes never learn cosmovisor exists.
#
# The check_upgrade_enclave.sh preflight above runs in BOTH branches on purpose: cosmovisor's
# post-swap restart bypasses run.sh entirely, so if the at-height handoff failed, the next manual
# restart through here is what retries it.  Do not "clean this up" by moving the detect above it.
if cosmovisor_managed && [[ -x "$qadenabin/cosmovisor" ]] ; then
    if [[ -n $EXTERNAL_ENCLAVE ]] ; then
        # The at-height hook tears down every enclave it finds; an operator's debugger-attached
        # enclave would be collateral.  Debug workflows stay on unmanaged nodes.
        echo "run.sh:  Error: --external-enclave cannot be combined with a cosmovisor-managed node"
        exit 1
    fi
    echo "run.sh: cosmovisor-managed (current -> $(readlink $QADENAHOME/cosmovisor/current))"
    # UNSAFE_SKIP_BACKUP=true by default: cosmovisor's pre-swap backup copies the whole data dir,
    # which on this fleet's disks would stall the upgrade at H for minutes and can fill the disk
    # outright.  History safety comes from the staged-binaries design, not from a data copy.
    # Every value is env-overridable by the caller.
    DAEMON_NAME="${DAEMON_NAME:-qadenad}"     DAEMON_HOME="${DAEMON_HOME:-$QADENAHOME}"     DAEMON_RESTART_AFTER_UPGRADE="${DAEMON_RESTART_AFTER_UPGRADE:-true}"     DAEMON_ALLOW_DOWNLOAD_BINARIES="${DAEMON_ALLOW_DOWNLOAD_BINARIES:-false}"     UNSAFE_SKIP_BACKUP="${UNSAFE_SKIP_BACKUP:-true}"     COSMOVISOR_CUSTOM_PREUPGRADE="${COSMOVISOR_CUSTOM_PREUPGRADE:-cosmovisor_preupgrade.sh}"     "$qadenabin/cosmovisor" run start --json-rpc.api eth,txpool,personal,net,debug,web3 --api.enable=true --grpc.enable=true --grpc.address 0.0.0.0:9090 --home=$QADENAHOME
    RC=$?
else
    $qadenabin/qadenad start --json-rpc.api eth,txpool,personal,net,debug,web3 --api.enable=true --grpc.enable=true --grpc.address 0.0.0.0:9090 --home=$QADENAHOME $EXTERNAL_ENCLAVE
    RC=$?
fi

echo "run.sh: ------------"
echo "run.sh: QADENA ENDED (rc $RC)"
echo "run.sh: ------------"

# Belt and braces: a clean shutdown already took the spawned enclaves along (SIGINT forwarding in
# the supervisor), but a PANIC exits without running handlers and orphans them.  Harmless -- the
# next start would adopt the orphan -- but a stopped node should leave a stopped machine.
if [[ -z $EXTERNAL_ENCLAVE ]] ; then
    if is_qadena_running ; then
        echo "run.sh: cleaning up enclave processes the node left behind"
        $qadenascripts/stop_qadena.sh --all
    fi
fi

exit $RC
