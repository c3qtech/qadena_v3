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

if [[ ! -d "$QADENAHOME/enclave_secrets" ]] ; then
    mkdir "$QADENAHOME/enclave_secrets"
fi

CHAINID=$(jq -r '.chain_id' "$QADENAHOME/config/genesis.json")

# enable core dumps
ulimit -c unlimited

# read the config and check log level
log_level=$(grep "log_level" $QADENAHOME/config/config.toml | awk '{print $3}' | tr -d '"' | tr -d "'")

# THE CHAIN'S PRUNING WINDOW, read from the same config/app.toml the chain reads and handed to
# the enclave at startup.  The enclave must retain at least as much history as the chain, or a
# rollback the chain accepts fails on the enclave and leaves the two at different heights.
# Passed as a flag rather than an RPC because the enclave starts BEFORE qadenad and must have
# its retention set before it loads its store.
toml_value() {
    grep "^$2[[:space:]]*=" "$1" 2>/dev/null | head -1 | cut -d= -f2- | tr -d ' "'"'"''
}
pruning_strategy=$(toml_value "$QADENAHOME/config/app.toml" "pruning")
pruning_keep_recent=$(toml_value "$QADENAHOME/config/app.toml" "pruning-keep-recent")
pruning_interval=$(toml_value "$QADENAHOME/config/app.toml" "pruning-interval")
[[ -z $pruning_strategy ]] && pruning_strategy="default"
[[ -z $pruning_keep_recent ]] && pruning_keep_recent=0
[[ -z $pruning_interval ]] && pruning_interval=0
echo "$(basename $0): chain pruning: $pruning_strategy keep-recent=$pruning_keep_recent interval=$pruning_interval"
if [[ $log_level == "debug" ]] ; then
    log_level="debug"
else
    log_level="info"
fi

# run qadenad_enclave until it exits with 20 or 10
while true; do
    $qadenabin/qadenad_enclave --home=$QADENAHOME --chain-id=$CHAINID --log-level $log_level --pruning=$pruning_strategy --pruning-keep-recent=$pruning_keep_recent --pruning-interval=$pruning_interval
    ret=$?
    if [[ $ret -eq 20 || $ret -eq 10 || $ret -eq 126 ]]; then
        echo "run_enclave.sh: qadenad_enclave exited with $ret"
        break
    else
        echo "run_enclave.sh: qadenad_enclave exited with $ret, retrying..."
    fi
    sleep 1
done



