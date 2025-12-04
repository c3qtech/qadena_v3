#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

qadenad_alias query qadena show-recover-key recover-al

qadenad_alias query qadena show-recover-key recover-ann

qadenad_alias query qadena show-recover-key recover-victor

qadenad_alias query qadena show-recover-key recover-jill
