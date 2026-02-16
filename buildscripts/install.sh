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
            echo "Usage: install.sh [--enclave] [--signer-enclave] [--chain] [--scripts] [--provider-scripts] [--testscripts] [--all]"
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

if [[ $install_enclave -eq 1 ]]; then
    echo "Installing enclave"
    enclave_path="$qadenabuild/cmd/qadenad_enclave"
    # check if reproducible_build_unique_id.txt exists and $enclave_path/qadenad_enclave
    if [[ -f "$enclave_path/reproducible_build_unique_id.txt" ]]; then
        unique_id=$(cat "$enclave_path/reproducible_build_unique_id.txt")
    else
        unique_id=$(cat "$enclave_path/test_unique_id.txt")
    fi
    cp $enclave_path/qadenad_enclave $qadenabin/qadenad_enclave.$unique_id
    cp $enclave_path/qadenad_enclave $qadenabin/qadenad_enclave
fi

if [[ $install_signer_enclave -eq 1 ]]; then
    echo "Installing signer enclave"
    signer_enclave_path="$qadenabuild/cmd/signer_enclave"
    # check if reproducible_build_unique_id.txt exists and $enclave_path/qadenad_enclave
    if [[ -f "$signer_enclave_path/reproducible_build_unique_id.txt" ]]; then
        unique_id=$(cat "$signer_enclave_path/reproducible_build_unique_id.txt")
    else
        unique_id=$(cat "$signer_enclave_path/test_unique_id.txt")
    fi
    cp $signer_enclave_path/signer_enclave $qadenabin/signer_enclave.$unique_id
    cp $signer_enclave_path/signer_enclave $qadenabin/signer_enclave
fi

if [[ $install_chain -eq 1 ]]; then
    echo "Installing chain"
    chain_path="$qadenabuild/cmd/qadenad"
    VERSION_FILE="$chain_path/version.txt"
    VERSION=$(cat "$VERSION_FILE")
    cp $chain_path/qadenad "$qadenabin/qadenad"
    cp $chain_path/qadenad $qadenabin/qadenad.$VERSION
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
    cp $qadenaproviderscripts/* "$QADENAHOME/provider_scripts/"
    if [[ ! -d "$QADENAHOME/veritas_scripts" ]] ; then
        mkdir -p "$QADENAHOME/veritas_scripts"
    fi
    cp $qadenaveritascripts/* "$QADENAHOME/veritas_scripts/"
fi

    