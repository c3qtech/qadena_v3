#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

qadenad_alias tx dsvs register-authorized-signatory al-eph --from al --yes

qadenad_alias tx dsvs register-authorized-signatory secdsvs-eph --from secdsvs --yes
