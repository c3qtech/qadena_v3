#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

guymnemonic="error raw awesome wheat junk envelope then brick brown ask blanket casual develop steak say often invite damage proud tenant van tone weekend police"
guy_a="8675"
guy_bf="3099"

./reuse_kyc_base.sh "unionbank-kyc-provider" "+639205551212" "coopnet-kyc-provider" "guy" `qadenad_alias query qadena convert-to-compressed-pc $guy_a $guy_bf`

qadenad_alias tx qadena create-wallet guy pioneer1 --account-mnemonic="$guymnemonic" --yes || exit 1
qadenad_alias tx qadena create-wallet guy-eph pioneer1 --link-to-real-wallet guy --account-mnemonic="$guymnemonic" --eph-account-index "1" --yes || exit 1
qadenad_alias tx qadena claim-credential $guy_a $guy_bf  personal-info --from guy --yes || exit 1






