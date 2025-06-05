#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

source "$qadenatestscripts/setup_mnemonic.sh"


qadenad_alias tx qadena create-wallet secdsvs pioneer1 sec-create-wallet-sponsor --account-mnemonic="$secdsvsmnemonic" --service-provider secdsvssrvprv  --yes || exit 1
qadenad_alias tx qadena create-wallet secdsvs-eph pioneer1 sec-create-wallet-sponsor --link-to-real-wallet secdsvs --account-mnemonic="$secdsvsmnemonic" --eph-account-index "1" --yes || exit 1

qadenad_alias tx qadena create-wallet al pioneer1 sec-create-wallet-sponsor --account-mnemonic="$almnemonic"  --service-provider secdsvssrvprv --yes || exit 1
qadenad_alias tx qadena create-wallet al-eph pioneer1 sec-create-wallet-sponsor --link-to-real-wallet al --account-mnemonic="$almnemonic" --eph-account-index "1" --yes || exit 1
qadenad_alias tx qadena create-wallet ann pioneer1 sec-create-wallet-sponsor --account-mnemonic="$annmnemonic"  --service-provider secdsvssrvprv --yes || exit 1
qadenad_alias tx qadena create-wallet ann-eph pioneer1 sec-create-wallet-sponsor --link-to-real-wallet ann --account-mnemonic="$annmnemonic" --eph-account-index "1" --yes || exit 1
qadenad_alias tx qadena create-wallet victor pioneer1 sec-create-wallet-sponsor --account-mnemonic="$victormnemonic"  --service-provider secdsvssrvprv --yes || exit 1
qadenad_alias tx qadena create-wallet victor-eph pioneer1 sec-create-wallet-sponsor --link-to-real-wallet victor --account-mnemonic="$victormnemonic" --eph-account-index "1" --yes || exit 1
qadenad_alias tx qadena create-wallet alexis pioneer1 sec-create-wallet-sponsor --account-mnemonic="$alexismnemonic"  --yes || exit 1
qadenad_alias tx qadena create-wallet alexis-eph pioneer1 sec-create-wallet-sponsor --link-to-real-wallet alexis --account-mnemonic="$alexismnemonic" --eph-account-index "1" --yes || exit 1
qadenad_alias tx qadena create-wallet kelvin pioneer1 sec-create-wallet-sponsor --account-mnemonic="$kelvinmnemonic"  --service-provider secdsvssrvprv --yes || exit 1
qadenad_alias tx qadena create-wallet kelvin-eph pioneer1 sec-create-wallet-sponsor --link-to-real-wallet kelvin --account-mnemonic="$kelvinmnemonic" --eph-account-index "1" --yes || exit 1

qadenad_alias tx qadena create-wallet jill pioneer1 sec-create-wallet-sponsor --account-mnemonic="$jillmnemonic"  --service-provider secdsvssrvprv --yes || exit 1
qadenad_alias tx qadena create-wallet jill-eph pioneer1 sec-create-wallet-sponsor --link-to-real-wallet jill --account-mnemonic="$jillmnemonic" --eph-account-index "1" --yes || exit 1
