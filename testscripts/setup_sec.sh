#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

identityprovidermnemonic="canoe oppose eternal occur film common dirt tomorrow lottery fun mask quote result account nasty tuna seat miracle have idle trophy frog catalog kiss"
dsvsprovidermnemonic="angry addict suit reform ostrich ride icon cushion park yellow wisdom mobile column sweet use anchor since tragic series ladder asthma dose prosper voice"
$qadenatestscripts/setup_provider.sh secidentitysrvprv identity --identity-provider-mnemonic $identityprovidermnemonic --count 10
$qadenatestscripts/setup_provider.sh secdsvssrvprv dsvs --identity-provider-mnemonic $dsvsprovidermnemonic --count 10

