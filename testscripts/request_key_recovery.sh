#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

source "$qadenatestscripts/setup_mnemonic.sh"


qadenad_alias tx qadena create-wallet recover-al pioneer1 --account-mnemonic="$recoveralmnemonic" --yes

qadenad_alias tx qadena create-credential $al_recover_a $al_recover_bf personal-info "rodolfo alberto" "asuncion" "villarica" "1970-Feb-02" "ph" "us" "M" --from pioneer1 --yes

qadenad_alias tx qadena claim-credential $al_recover_a $al_recover_bf personal-info --from recover-al --recover-key --yes


qadenad_alias tx qadena create-wallet recover-ann pioneer1 --account-mnemonic="$recoverannmnemonic" --yes

qadenad_alias tx qadena create-credential $ann_recover_a $ann_recover_bf personal-info "ann" "a" "cuisia" "1965-Jan-01" "au" "au" "M" --from pioneer1 --yes

qadenad_alias tx qadena claim-credential $ann_recover_a $ann_recover_bf personal-info --from recover-ann --recover-key --yes

qadenad_alias tx qadena create-wallet recover-victor pioneer1 --account-mnemonic="$recovervictormnemonic" --yes

qadenad_alias tx qadena create-credential $victor_recover_a $victor_recover_bf personal-info "victor" "b" "torres" "1970-Feb-03" "ph" "ph" "M" --from pioneer1 --yes || exit 1

qadenad_alias tx qadena claim-credential $victor_recover_a $victor_recover_bf personal-info --from recover-victor --recover-key --yes
