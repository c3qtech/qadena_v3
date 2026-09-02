#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

# The devnet's validator is `pioneer1`; a launch chain names its own.  Env-defaulted so a
# whole suite run can be pointed at either without editing every script.
pioneer="${QADENA_PIONEER:-pioneer1}"

source "$qadenatestscripts/setup_mnemonic.sh"

# we need to use a sub-wallet when escrowing a key, like '--from al-eph2'

echo "-------------------------"
echo "Protect al's seed phrase"
echo "-------------------------"
qadenad_alias tx qadena protect-key "$almnemonic" 2 "$pioneer" "+63288888802" victortorres@c3qtech.com --from al-eph1 --yes

echo "-------------------------"
echo "Protect ann's seed phrase"
echo "-------------------------"
qadenad_alias tx qadena protect-key "$annmnemonic" 1 victortorres@c3qtech.com --from ann-eph1 --yes

echo "-------------------------"
echo "Protect victor's seed phrase"
echo "-------------------------"
qadenad_alias tx qadena protect-key "$victormnemonic" 0 "$pioneer" --from victor-eph1 --yes

