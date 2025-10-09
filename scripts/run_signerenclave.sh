#!/bin/zsh

echo "run_signerenclave.sh: starting..."

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

# enable core dumps
ulimit -c unlimited

# run signer_enclave until it exits with 20 or 10
while true; do
    $qadenabin/signer_enclave --home=$QADENAHOME --addr=127.0.0.1:26659
    ret=$?
    if [[ $ret -eq 20 || $ret -eq 10 || $ret -eq 126 ]]; then
        echo "run_signerenclave.sh: signer_enclave exited with $ret"
        break
    else
        echo "run_signerenclave.sh: signer_enclave exited with $ret, retrying..."
    fi
    sleep 1
done
