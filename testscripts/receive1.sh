#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

# receive from ann-eph to ann
qadenad_alias tx qadena receive-funds ann-eph 0qdn --from ann --yes
