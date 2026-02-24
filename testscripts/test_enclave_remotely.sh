#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

# get one parameter
if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <hex-report>"
    exit 1
fi

needs_root_if_real_enclave "test_enclave_locally.sh"

ego run $qadenabin/qadenad_enclave --test-remote-report-hex $1 -log-level debug --home $QADENAHOME --realenclave
