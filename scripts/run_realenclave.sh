#!/bin/zsh

echo "run_realenclave.sh: starting..."

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

if [[ ! -d "$QADENAHOME/enclave_config" ]] ; then
    mkdir "$QADENAHOME/enclave_config"
fi

if [[ ! -d "$QADENAHOME/enclave_data" ]] ; then
    mkdir "$QADENAHOME/enclave_data"
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

if [ $IS_UP -eq 1 ] ; then
   while true; do
       ego run $qadenabin/qadenad_enclave --realenclave --home=$QADENAHOME --chain-id=$CHAINID
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
