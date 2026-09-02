#!/bin/zsh
#
# A hand-run helper, NOT part of the regression suite -- regression.sh:752 says so explicitly, and
# the recovery cases it does run live in test_credentials.sh.
#
# These signatures carry no guardian identity assertion, which is fine at
# sign_recover_key_guardian_assertion_mode 0 or 1 and REFUSED at 2 for the institutional signers
# below (`--from "$pioneer"` is institutional too, not just the --is-service-provider lines; only the
# --is-user ones are exempt).  Pass --guardian-credential-hash <hex> to sign under an enforcing
# chain.  test_credentials.sh explains the classification and what has to ship first.

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

# The devnet's validator is `pioneer1`; a launch chain names its own.  Env-defaulted so a
# whole suite run can be pointed at either without editing every script.
pioneer="${QADENA_PIONEER:-pioneer1}"

source "$qadenatestscripts/setup_mnemonic.sh"

#qadenad_alias query qadena show-recover-key recover-al
#qadenad_alias query qadena show-recover-key recover-ann
#qadenad_alias query qadena show-recover-key recover-victor

qadenad_alias tx qadena sign-recover-key al-eph1 --from victor-eph1 --is-user --yes
qadenad_alias tx qadena sign-recover-key al-eph1 --from "$pioneer" --yes

qadenad_alias tx qadena sign-recover-key ann-eph1 --from victor-eph1 --is-user --yes

qadenad_alias tx qadena sign-recover-key jill-eph1 --from victor-eph1 --is-user --yes
qadenad_alias tx qadena sign-recover-key jill-eph1 --from "$pioneer" --yes
qadenad_alias tx qadena sign-recover-key jill-eph1 --from testidentitysrvprv --is-service-provider --yes


