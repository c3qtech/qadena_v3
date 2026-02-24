#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

needs_root_if_real_enclave "test_enclave_locally.sh"

ego run $qadenabin/qadenad_enclave --test-remote-report-locally -log-level debug --home $QADENAHOME --realenclave
