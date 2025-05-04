#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

source "$qadenatestscripts/setup_mnemonic.sh"


echo "----------------------------------"
echo "Binding credentials to sub-wallets"
echo "----------------------------------"

qadenad_alias tx nameservice bind-credential al phone-contact-info --from al-eph2 --yes || exit 1
qadenad_alias tx nameservice bind-credential al email-contact-info --from al-eph2 --yes || exit 1
qadenad_alias tx nameservice bind-credential ann phone-contact-info --from ann-eph2 --yes || exit 1
qadenad_alias tx nameservice bind-credential ann email-contact-info --from ann-eph2 --yes || exit 1
qadenad_alias tx nameservice bind-credential victor email-contact-info --from victor-eph --yes || exit 1
qadenad_alias tx nameservice bind-credential alexis email-contact-info --from alexis-eph --yes || exit 1
qadenad_alias tx nameservice bind-credential kelvin email-contact-info --from kelvin-eph --yes || exit 1
qadenad_alias query nameservice list-name-binding || exit 1
