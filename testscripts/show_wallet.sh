#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

qadenad_alias query qadena show-wallet $(qadenad_alias keys show $1 -a) --decrypt-as $(qadenad_alias keys show $1 -a)

