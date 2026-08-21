#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

# install scripts
# get flags --enclave-only, --chain-only, --scripts-only
install_enclave=0
install_signer_enclave=0
install_chain=0
install_scripts=0
install_provider_scripts=0
install_testscripts=0
hold=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --enclave)
            install_enclave=1
            shift
            ;;
        --signer-enclave)
            install_signer_enclave=1
            shift
            ;;
        --chain)
            install_chain=1
            shift
            ;;
        --scripts)
            install_scripts=1
            shift
            ;;
        --provider-scripts)
            install_provider_scripts=1
            shift
            ;;
        --testscripts)
            install_testscripts=1
            shift
            ;;
        --hold)
            # HOLD THE NEW BINARY BACK.  Install qadenad_enclave.<uniqueID> but leave the LIVE
            # binary alone, so the node keeps running what it is running and nothing has to stop.
            #
            # This is the only correct order on real SGX, where MRENCLAVE is a hash of the built
            # image and therefore CANNOT be known before the build: build --hold, read the
            # measurement off the artifact (ego uniqueid), register it by governance, wait for it to
            # go active, and only then swap it in with scripts/activate_enclave.sh.
            #
            # Swapping first is what leaves a node down: the old enclave refuses to hand its sealed
            # keys to a measurement the chain has not made active.
            hold=1
            shift
            ;;
        --all)
            install_enclave=1
            install_signer_enclave=1
            install_chain=1
            install_scripts=1
            install_provider_scripts=1
            install_testscripts=1
            shift
            ;;
        --help)
            echo "Usage: install.sh [--enclave] [--signer-enclave] [--chain] [--scripts] [--provider-scripts] [--testscripts] [--all] [--hold]"
            echo "  --hold  install qadenad_enclave.<uniqueID> only; do not replace the live binary"
            echo "          (and do not stop the node).  Required on SGX, where the measurement is"
            echo "          only knowable after the build.  Activate later with activate_enclave.sh."
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# need at least one
if [[ $install_enclave -eq 0  && $install_signer_enclave -eq 0 && $install_chain -eq 0 && $install_scripts -eq 0 && $install_testscripts -eq 0 && $install_provider_scripts -eq 0 ]]; then
    echo "Error: Need at least one option: --enclave, --signer-enclave, --chain, --scripts, --provider-scripts, or --all"
    exit 1
fi

# INSTALLING A BINARY OVER A RUNNING NODE SILENTLY DOES NOTHING.
#
# These were plain `cp`, unchecked.  Copying to qadenad_enclave.<uniqueID> succeeds (a new filename
# is never busy) while copying to the LIVE qadenad_enclave fails with "Text file busy" -- and with
# the error discarded, the build prints "Install done" and exits 0 while the node keeps running the
# OLD binary.  Every other signal says the deploy worked.
#
# That cost two separate debugging sessions on 2026-08-21: a staged qadenad_enclave.unique049
# appeared next to an unchanged live binary, and the mismatch was only found by hashing them.
#
# So: stop the node before touching any binary, refuse to continue if it will not stop, and check
# every copy.  Scripts and test data are NOT binaries and do not require this -- installing those
# over a running node is fine and is done routinely.
#
# THE NODE IS LEFT STOPPED.  Restarting is the caller's decision, because the caller is usually
# doing something else next -- run.sh performs the enclave upgrade check on the way up, and starting
# here would race it.
node_stopped=0
ensure_stopped_for_binaries() {
    [[ $node_stopped -eq 1 ]] && return 0

    # NEVER INSIDE THE BUILD CONTAINER.  build.sh re-invokes itself with DOCKER_BUILD=1 for the SGX
    # reproducible build, and that inner invocation does not carry --hold.  A build container has no
    # node to stop -- but the SGX builder is privileged and bind-mounts $QADENAHOME (it needs
    # /dev/sgx), so stop_qadena.sh reached out of the container and stopped the REAL node on the
    # host, halting a chain at height 98145 during what was supposed to be a --hold build that
    # touched nothing.
    #
    # Guarding on DOCKER_BUILD rather than on --hold on purpose: the flag has to be threaded through
    # correctly to help, and this must hold even when it is not.  Stopping a node is never the right
    # thing to do from inside a build.
    if [[ "$DOCKER_BUILD" = "1" ]]; then
        echo "  (inside the build container -- not stopping anything)"
        node_stopped=1
        return 0
    fi
    echo "Stopping the node before installing binaries (a running binary cannot be replaced)"
    "$qadenascripts/stop_qadena.sh" --all > /dev/null 2>&1
    local alive
    alive=$(( $(pgrep -cx qadenad) + $(pgrep -cx qadenad_enclave) + $(pgrep -cx signer_enclave) ))
    if [[ $alive -ne 0 ]]; then
        echo "Error: $alive qadena process(es) still running after stop_qadena.sh --all."
        echo "       Refusing to install over them -- the copy would fail silently and you would be"
        echo "       left running the old binary while this script reported success."
        exit 1
    fi
    node_stopped=1
    echo "Node stopped.  It is NOT restarted by this script -- start it when you are ready."
}

# install_binary <src> <dst> -- a cp whose failure is fatal.
install_binary() {
    if ! cp "$1" "$2"; then
        echo "Error: failed to install $2 (from $1)"
        exit 1
    fi
}

if [[ $install_enclave -eq 1 ]]; then
    echo "Installing enclave"
    [[ $hold -eq 0 ]] && ensure_stopped_for_binaries
    enclave_path="$qadenabuild/cmd/qadenad_enclave"
    # check if reproducible_build_unique_id.txt exists and $enclave_path/qadenad_enclave
    if [[ -f "$enclave_path/reproducible_build_unique_id.txt" ]]; then
        unique_id=$(cat "$enclave_path/reproducible_build_unique_id.txt")
    else
        unique_id=$(cat "$enclave_path/test_unique_id.txt")
    fi
    install_binary "$enclave_path/qadenad_enclave" "$qadenabin/qadenad_enclave.$unique_id"
    if [[ $hold -eq 1 ]]; then
        echo "  held back: staged as qadenad_enclave.$unique_id; the live binary is unchanged"
        echo "  register it, wait for active, then: scripts/activate_enclave.sh $unique_id"
    else
        install_binary "$enclave_path/qadenad_enclave" "$qadenabin/qadenad_enclave"
    fi
fi

if [[ $install_signer_enclave -eq 1 ]]; then
    echo "Installing signer enclave"
    [[ $hold -eq 0 ]] && ensure_stopped_for_binaries
    signer_enclave_path="$qadenabuild/cmd/signer_enclave"
    # check if reproducible_build_unique_id.txt exists and $enclave_path/qadenad_enclave
    if [[ -f "$signer_enclave_path/reproducible_build_unique_id.txt" ]]; then
        unique_id=$(cat "$signer_enclave_path/reproducible_build_unique_id.txt")
    else
        unique_id=$(cat "$signer_enclave_path/test_unique_id.txt")
    fi
    install_binary "$signer_enclave_path/signer_enclave" "$qadenabin/signer_enclave.$unique_id"
    if [[ $hold -eq 1 ]]; then
        echo "  held back: staged as signer_enclave.$unique_id; the live binary is unchanged"
    else
        install_binary "$signer_enclave_path/signer_enclave" "$qadenabin/signer_enclave"
    fi
fi

if [[ $install_chain -eq 1 ]]; then
    echo "Installing chain"
    [[ $hold -eq 0 ]] && ensure_stopped_for_binaries
    chain_path="$qadenabuild/cmd/qadenad"
    VERSION_FILE="$chain_path/version.txt"
    VERSION=$(cat "$VERSION_FILE")
    install_binary "$chain_path/qadenad" "$qadenabin/qadenad.$VERSION"
    if [[ $hold -eq 1 ]]; then
        echo "  held back: staged as qadenad.$VERSION; the live binary is unchanged"
    else
        install_binary "$chain_path/qadenad" "$qadenabin/qadenad"
    fi
    cp $qadenabuild/vendor/github.com/CosmWasm/wasmvm/v2/internal/api/*.so $qadenabin/
fi

if [[ $install_scripts -eq 1 ]]; then
    echo "Installing scripts"
    if [[ ! -d "$QADENAHOME/scripts" ]] ; then
        mkdir -p "$QADENAHOME/scripts"
    fi
    cp $qadenascripts/* "$QADENAHOME/scripts/"
    cp $qadenabuild/config.yml "$QADENAHOME/config"
    cp $qadenabuild/cmd/qadenad_enclave/public.pem "$QADENAHOME/config/public.pem"
fi

if [[ $install_testscripts -eq 1 ]]; then
    echo "Installing testscripts and test_data"
    if [[ ! -d "$QADENAHOME/testscripts" ]] ; then
        mkdir -p "$QADENAHOME/testscripts"
    fi
    if [[ ! -d "$QADENAHOME/test_data" ]] ; then
        mkdir -p "$QADENAHOME/test_data"
    fi
    cp $qadenatestscripts/* "$QADENAHOME/testscripts/"
    cp $qadenabuild/test_data/* "$QADENAHOME/test_data/"
fi

if [[ $install_provider_scripts -eq 1 ]]; then
    echo "Installing provider scripts"
    if [[ ! -d "$QADENAHOME/provider_scripts" ]] ; then
        mkdir -p "$QADENAHOME/provider_scripts"
    fi
    cp -r $qadenaproviderscripts/* "$QADENAHOME/provider_scripts/"
    if [[ ! -d "$QADENAHOME/veritas_scripts" ]] ; then
        mkdir -p "$QADENAHOME/veritas_scripts"
    fi
    cp $veritasscripts/* "$QADENAHOME/veritas_scripts/"
fi

echo "Install done."    