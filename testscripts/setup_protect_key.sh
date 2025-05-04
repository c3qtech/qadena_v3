#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

source "$qadenatestscripts/setup_mnemonic.sh"

# we need to use a sub-wallet when escrowing a key, like '--from al-eph2'

echo "-------------------------"
echo "Protect al's seed phrase"
echo "-------------------------"
qadenad_alias tx qadena protect-key "$almnemonic" 2 pioneer1 "+639065551234" victortorres@c3qtech.com --from al-eph --yes

echo "-------------------------"
echo "Protect ann's seed phrase"
echo "-------------------------"
qadenad_alias tx qadena protect-key "$annmnemonic" 1 victortorres@c3qtech.com --from ann-eph2 --yes

echo "-------------------------"
echo "Protect victor's seed phrase"
echo "-------------------------"
qadenad_alias tx qadena protect-key "$victormnemonic" 0 pioneer1 --from victor-eph --yes

