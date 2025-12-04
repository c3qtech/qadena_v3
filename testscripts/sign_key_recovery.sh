#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

source "$qadenatestscripts/setup_mnemonic.sh"

#qadenad_alias query qadena show-recover-key recover-al
#qadenad_alias query qadena show-recover-key recover-ann
#qadenad_alias query qadena show-recover-key recover-victor

qadenad_alias tx qadena sign-recover-key al-eph1 --from victor-eph1 --is-user --yes
qadenad_alias tx qadena sign-recover-key al-eph1 --from pioneer1 --yes

qadenad_alias tx qadena sign-recover-key ann-eph1 --from victor-eph1 --is-user --yes

qadenad_alias tx qadena sign-recover-key jill-eph1 --from victor-eph1 --is-user --yes
qadenad_alias tx qadena sign-recover-key jill-eph1 --from pioneer1 --yes
qadenad_alias tx qadena sign-recover-key jill-eph1 --from testidentitysrvprv --is-service-provider --yes


