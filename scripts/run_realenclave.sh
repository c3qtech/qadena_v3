#!/bin/zsh

echo "run_realenclave.sh: starting..."

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

# `ego run` below OPENS /dev/sgx_enclave, so check reachability here too.  run.sh already gates
# this, but this script is also launched directly and by restart_qadena.sh -- and an ungated
# start fails inside ego with a device error rather than the message that names the fix.
needs_root_if_real_enclave "run_realenclave.sh" "$qadenabin/qadenad_enclave"

if [[ ! -d "$QADENAHOME/enclave_config" ]] ; then
    mkdir "$QADENAHOME/enclave_config"
fi

if [[ ! -d "$QADENAHOME/enclave_data" ]] ; then
    mkdir "$QADENAHOME/enclave_data"
fi

if [[ ! -d "$QADENAHOME/enclave_secrets" ]] ; then
    mkdir "$QADENAHOME/enclave_secrets"
fi


if dpkg -V az-dcap-client ; then
    echo "run_realenclave.sh: Running in Azure"
    IS_UP=1
else
    echo "run_realenclave.sh: Checking if Intel PCCS (Provisioning Certificate Caching Service) docker is already installed"
    if docker container ls -a | grep pccs > /dev/null ; then
	echo "run_realenclave.sh: Intel PCCS docker already installed."
	if docker ps | grep pccs > /dev/null ; then
	    echo "run_realenclave.sh: Intel PCCS docker container already started, checking status..."
	    
	    if curl --fail -k https://localhost:8081/sgx/certification/v4/rootcacrl > /dev/null 2> /dev/null ; then
		echo "run_realenclave.sh: Intel PCCS is working!"
	    else
		echo "run_realenclave.sh: Intel PCCS is not working.  Trying to recover by restarting it."
		docker stop pccs
		docker start pccs
	    fi
	    
	else
	    echo "run_realenclave.sh: Starting Intel PCCS docker container"
	    docker start pccs
	fi
    else
	echo "run_realenclave.sh: Intel PCCS is not installed, installing and running"
	docker run -p 8081:8081 --name pccs -d ghcr.io/edgelesssys/pccs
    fi
    
    echo "run_realenclave.sh: Testing if Intel PCCS is working"
    
    IS_UP=0
    for i in 1 2 3 4 5
    do
	if curl --fail -k https://localhost:8081/sgx/certification/v4/rootcacrl > /dev/null 2> /dev/null ; then
	    echo "run_realenclave.sh: Intel PCCS is working!"
	    IS_UP=1
	    break
	else
	    echo "run_realenclave.sh: Intel PCCS is not yet up, waiting...$i"
	    sleep 3
	fi
    done
fi

CHAINID=$(jq -r '.chain_id' "$QADENAHOME/config/genesis.json")

# THE SGX ENCLAVE GETS A LOG LEVEL TOO, exactly as the debug one does in run_enclave.sh.
#
# It never did, so every c.LoggerDebug call inside a real enclave was silently dropped while the
# same code logged normally in debug mode.  The asymmetry is invisible until something goes wrong
# under SGX and the log that would explain it does not exist: an enclave identity sat at "inactive"
# with ZERO log lines about the promotion check, which reads as "the code never ran" and actually
# meant "the code cannot say anything".
#
# Same derivation as run_enclave.sh, so both modes agree with config.toml.
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

if [ $IS_UP -eq 1 ] ; then
   while true; do
       ego run $qadenabin/qadenad_enclave --realenclave --home=$QADENAHOME --chain-id=$CHAINID --log-level $log_level --pruning=$pruning_strategy --pruning-keep-recent=$pruning_keep_recent --pruning-interval=$pruning_interval
       ret=$?
       if [[ $ret -eq 20 || $ret -eq 10 || $ret -eq 1 || $ret -eq 2 ]]; then
           echo "run_realenclave.sh: qadenad_enclave exited with $ret"
           break
       else
           echo "run_realenclave.sh: qadenad_enclave exited with $ret, retrying..."
       fi
       sleep 1
   done
else
    echo "run_realenclave.sh: Could not run the real enclave because Intel PCCS is not running, or Azure DCAP is not installed."
    exit 1
fi
