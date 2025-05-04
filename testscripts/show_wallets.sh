#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"


$qadenatestscripts/show_wallet.sh al
$qadenatestscripts/show_wallet.sh al-eph
$qadenatestscripts/show_wallet.sh ann
$qadenatestscripts/show_wallet.sh ann-eph

