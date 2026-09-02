#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

# The devnet's validator is `pioneer1`; a launch chain names its own.  Env-defaulted so a
# suite run can target either without editing every create-wallet call.
pioneer="${QADENA_PIONEER:-pioneer1}"

source "$qadenatestscripts/setup_mnemonic.sh"


qadenad_alias tx qadena create-wallet secdsvs "$pioneer" sec-create-wallet-sponsor --account-mnemonic="$secdsvsmnemonic" --service-provider secdsvssrvprv  --yes || exit 1
qadenad_alias tx qadena create-wallet secdsvs-eph "$pioneer" sec-create-wallet-sponsor --link-to-real-wallet secdsvs --account-mnemonic="$secdsvsmnemonic" --eph-account-index "1" --yes || exit 1

qadenad_alias tx qadena create-wallet al "$pioneer" sec-create-wallet-sponsor --account-mnemonic="$almnemonic"  --service-provider secdsvssrvprv --yes || exit 1
qadenad_alias tx qadena create-wallet al-eph "$pioneer" sec-create-wallet-sponsor --link-to-real-wallet al --account-mnemonic="$almnemonic" --eph-account-index "1" --yes || exit 1
qadenad_alias tx qadena create-wallet ann "$pioneer" sec-create-wallet-sponsor --account-mnemonic="$annmnemonic"  --service-provider secdsvssrvprv --yes || exit 1
qadenad_alias tx qadena create-wallet ann-eph "$pioneer" sec-create-wallet-sponsor --link-to-real-wallet ann --account-mnemonic="$annmnemonic" --eph-account-index "1" --yes || exit 1
qadenad_alias tx qadena create-wallet victor "$pioneer" sec-create-wallet-sponsor --account-mnemonic="$victormnemonic"  --service-provider secdsvssrvprv --yes || exit 1
qadenad_alias tx qadena create-wallet victor-eph "$pioneer" sec-create-wallet-sponsor --link-to-real-wallet victor --account-mnemonic="$victormnemonic" --eph-account-index "1" --yes || exit 1
qadenad_alias tx qadena create-wallet alexis "$pioneer" sec-create-wallet-sponsor --account-mnemonic="$alexismnemonic"  --yes || exit 1
qadenad_alias tx qadena create-wallet alexis-eph "$pioneer" sec-create-wallet-sponsor --link-to-real-wallet alexis --account-mnemonic="$alexismnemonic" --eph-account-index "1" --yes || exit 1
qadenad_alias tx qadena create-wallet kelvin "$pioneer" sec-create-wallet-sponsor --account-mnemonic="$kelvinmnemonic"  --service-provider secdsvssrvprv --yes || exit 1
qadenad_alias tx qadena create-wallet kelvin-eph "$pioneer" sec-create-wallet-sponsor --link-to-real-wallet kelvin --account-mnemonic="$kelvinmnemonic" --eph-account-index "1" --yes || exit 1

qadenad_alias tx qadena create-wallet jill "$pioneer" sec-create-wallet-sponsor --account-mnemonic="$jillmnemonic"  --service-provider secdsvssrvprv --yes || exit 1
qadenad_alias tx qadena create-wallet jill-eph "$pioneer" sec-create-wallet-sponsor --link-to-real-wallet jill --account-mnemonic="$jillmnemonic" --eph-account-index "1" --yes || exit 1
