#!/bin/zsh

echo "run_enclave.sh: starting..."

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

if [[ ! -d "$QADENAHOME/enclave_config" ]] ; then
    mkdir "$QADENAHOME/enclave_config"
fi

if [[ ! -d "$QADENAHOME/enclave_data" ]] ; then
    mkdir "$QADENAHOME/enclave_data"
fi


if [[ "$(uname -s)" == "Darwin" ]] ; then
    echo "run_enclave.sh: setting window title..."
    echo -n -e "\033]0;QADENAD Enclave Debug Window\007"
fi

CHAINID=$(jq -r '.chain_id' "$QADENAHOME/config/genesis.json")

# enable core dumps
ulimit -c unlimited

# run qadenad_enclave until it exits with 20 or 10
while true; do
    $qadenabin/qadenad_enclave --home=$QADENAHOME --chain-id=$CHAINID
    ret=$?
    if [[ $ret -eq 20 || $ret -eq 10 || $ret -eq 126 ]]; then
        echo "run_enclave.sh: qadenad_enclave exited with $ret"
        break
    else
        echo "run_enclave.sh: qadenad_enclave exited with $ret, retrying..."
    fi
    sleep 1
done



