#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

# transfer from al to ann-eph
qadenad_alias tx qadena transfer-funds ann-eph1 123qdn 0qdn --transfer-note "this is my first transfer" --from al --yes
