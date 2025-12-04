#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

source "$qadenatestscripts/setup_mnemonic.sh"


qadenad_alias tx qadena create-wallet recover-al pioneer1 --account-mnemonic="$recoveralmnemonic" create-wallet-sponsor --yes

qadenad_alias tx qadena create-credential $al_recover_a $al_recover_bf personal-info "rodolfo alberto" "asuncion" "villarica" "1970-Feb-02" "ph" "us" "M" --from testidentitysrvprv --yes

qadenad_alias tx qadena claim-credential $al_recover_a $al_recover_bf personal-info --from recover-al --recover-key --yes


qadenad_alias tx qadena create-wallet recover-ann pioneer1 --account-mnemonic="$recoverannmnemonic" create-wallet-sponsor --yes

qadenad_alias tx qadena create-credential $ann_recover_a $ann_recover_bf personal-info "ann" "a" "cuisia" "1970-Jan-01" "ph" "ph" "f" --from testidentitysrvprv --yes

qadenad_alias tx qadena claim-credential $ann_recover_a $ann_recover_bf personal-info --from recover-ann --recover-key --yes

qadenad_alias tx qadena create-wallet recover-victor pioneer1 --account-mnemonic="$recovervictormnemonic" create-wallet-sponsor --yes

qadenad_alias tx qadena create-credential $victor_recover_a $victor_recover_bf personal-info "victor" "v" "torres" "1980-Jan-02" "ph" "ph" "M" --from testidentitysrvprv --yes || exit 1

qadenad_alias tx qadena claim-credential $victor_recover_a $victor_recover_bf personal-info --from recover-victor --recover-key --yes

# jill

qadenad_alias tx qadena create-wallet recover-jill pioneer1 --account-mnemonic="$recoverjillmnemonic" create-wallet-sponsor --yes

qadenad_alias tx qadena create-credential $jill_recover_a $jill_recover_bf personal-info "jill" "lava" "quimba" "1980-Jan-01" "ph" "ph" "f" --from testidentitysrvprv --yes || exit 1

qadenad_alias tx qadena claim-credential $jill_recover_a $jill_recover_bf personal-info --from recover-jill --recover-key --yes
