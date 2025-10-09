#!/bin/zsh

echo "run_realsignerenclave.sh: starting..."

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

while true; do
    ego run $qadenabin/signer_enclave --real-enclave --home=$QADENAHOME --addr=127.0.0.1:26659
    ret=$?
    if [[ $ret -eq 20 || $ret -eq 10 || $ret -eq 1 || $ret -eq 2 ]]; then
        echo "run_realsignerenclave.sh: signer_enclave exited with $ret"
        break
    else
        echo "run_realsignerenclave.sh: signer_enclave exited with $ret, retrying..."
    fi
    sleep 1
done
