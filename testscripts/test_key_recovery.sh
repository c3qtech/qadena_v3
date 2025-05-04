#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

$qadenatestscripts/request_key_recovery.sh
$qadenatestscripts/sign_key_recovery.sh
$qadenatestscripts/show_key_recovery.sh
