#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

# THE CONTRACT IS "A NODE IS RUNNING WHEN THIS RETURNS 0", not "I attempted a start".
#
# It used to be the latter, and the difference cost a fleet join on 2026-08-30.  Both exit paths
# below returned 0 without any node being up afterwards:
#
#   - "already running" returned immediately.  A node that is up AT THIS INSTANT may be a transient
#     -- add_full_node.sh leaves one briefly during the join -- so the caller was told the node was
#     started, the transient then died seconds later, and nth_node_bringup reported "no qadenad
#     process appeared" against a node nobody had actually started.  Observed exactly: qadenad alive
#     22:38:12, gone 22:38:51, and $QADENAHOME/logs was never created because restart_qadena.sh had
#     never run.
#   - the start path returned restart_qadena.sh's status, which is the status of BACKGROUNDING the
#     pipeline, not of the node coming up.
#
# So every path now ends at ensure_running, which verifies rather than assumes.  A caller that needs
# a node -- every caller -- can now trust the exit status.

# STABILITY, NOT PRESENCE.  A single is_qadena_running says the node exists right now; it does not
# say it will exist in ten seconds, which is precisely the transient that caused the incident.  Two
# observations separated by a settle interval distinguish "running" from "on its way out".
QADENA_START_SETTLE=${QADENA_START_SETTLE:-8}
node_is_stable() {
    is_qadena_running || return 1
    sleep "$QADENA_START_SETTLE"
    is_qadena_running
}

# ensure_running -- return 0 only when a node is up and has stayed up.
#
# GENEROUS ON PURPOSE.  On real SGX the enclave loads before qadenad appears, and that took ~50s on
# SGX2; on ARM it is seconds.  One number has to cover both, and waiting too long merely delays a
# report while waiting too little invents a failure -- which is the bug this replaces.
#
# The restart is attempted at most twice.  Retrying forever would paper over a node that cannot
# start, and two attempts is exactly what the transient case needs: the first observation catches a
# dying transient, the second starts a real one.
ensure_running() {
    local deadline=$((SECONDS + ${QADENA_START_TIMEOUT:-240}))
    local attempts=0
    while (( SECONDS < deadline )); do
        if node_is_stable; then
            echo "start_qadena.sh: node is running $(qadena_supervision_tag)"
            return 0
        fi
        if is_qadena_running; then
            # Present but not stable: it is going down.  Let it finish before starting another,
            # or the new one races the old one's enclave for /tmp/qadena_*.sock.
            echo "start_qadena.sh: a node was running but did not stay up -- waiting for it to settle"
            sleep 5
            continue
        fi
        if (( attempts >= 2 )); then
            sleep 5
            continue
        fi
        (( attempts++ ))
        echo "start_qadena.sh: no node running -- starting (attempt $attempts)"
        if qadena_systemd_managed; then
            sudo systemctl start qadena
        else
            "$qadenascripts/restart_qadena.sh" --skip-stop
        fi
        sleep 5
    done
    echo "start_qadena.sh: ERROR: no node is running after ${QADENA_START_TIMEOUT:-240}s."
    echo "  This is a FAILURE TO START, not a slow start -- the wait already covers a real SGX"
    echo "  enclave load.  Check \$QADENAHOME/logs; if that directory is absent, run.sh never got"
    echo "  as far as its logging pipeline."
    return 1
}

# UNDER SYSTEMD, ASK SYSTEMD.  Launching run.sh directly would put a second node beside the one
# the unit manages, and the unit would still be free to restart its own.
#
# NOT `exec` ANY MORE: exec replaces this shell, so nothing could verify the result.  That is the
# same "attempted, therefore fine" assumption as the other path.
if qadena_systemd_managed; then
    if systemctl is-active --quiet qadena; then
        echo "start_qadena.sh: qadena.service is already active (systemd supervised)"
    else
        echo "start_qadena.sh: systemd unit present (qadena.service $(qadena_unit_state)) -- starting qadena.service"
        echo "start_qadena.sh: START QADENA $(qadena_supervision_tag)"
        sudo systemctl start qadena
    fi
    ensure_running
    exit $?
fi

if is_qadena_running; then
    echo "Qadena is already running $(qadena_supervision_tag)"
else
    echo "start_qadena.sh: START QADENA $(qadena_supervision_tag)"
    "$qadenascripts/restart_qadena.sh" --skip-stop
fi

ensure_running
exit $?
