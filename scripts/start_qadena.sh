#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

if is_qadena_running; then
    echo "Qadena is already running"
    exit 0
fi

$qadenascripts/restart_qadena.sh --skip-stop