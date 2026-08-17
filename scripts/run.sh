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
$qadenabin/qadenad start --json-rpc.api eth,txpool,personal,net,debug,web3 --api.enable=true --grpc.enable=true --grpc.address 0.0.0.0:9090 --home=$QADENAHOME $EXTERNAL_ENCLAVE
RC=$?

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
