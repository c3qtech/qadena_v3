#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

# UNDER SYSTEMD, ASK SYSTEMD.  Launching run.sh directly would put a second node beside the one
# the unit manages, and the unit would still be free to restart its own.
if qadena_systemd_managed; then
    if systemctl is-active --quiet qadena; then
        echo "start_qadena.sh: qadena.service is already active"
        exit 0
    fi
    echo "start_qadena.sh: systemd unit present -- starting qadena.service"
    exec sudo systemctl start qadena
fi

if is_qadena_running; then
    echo "Qadena is already running"
    exit 0
fi

$qadenascripts/restart_qadena.sh --skip-stop