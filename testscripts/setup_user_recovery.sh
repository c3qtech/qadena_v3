#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

user=$1
mnemonic=$2
required=$3
partners=$4

echo "-------------------------"
echo "Protect $user's seed phrase"
echo "-------------------------"
qadenad_alias tx qadena protect-key "$mnemonic" $required ${(s: :)partners} --from $user-eph --yes

