#!/bin/zsh
#
# Fault injection reproducing the 2026-08-09 incident shape: the enclave stops responding
# mid-run.  The node must HALT (haltOnEnclaveFailure) rather than commit enclave-less blocks --
# on the real network the old behaviour finalised 31,675 blocks a healthy peer had rejected --
# and after the enclave returns, a restart must reconcile and resume.
#
# The stall is injected with SIGSTOP, not SIGKILL, for two reasons: it matches the incident (the
# enclave hung inside an OOM before dying), and it is deterministic -- a SIGKILLed simulation
# enclave is respawned by run_enclave.sh within a couple of seconds, which can win the race
# against the chain's next RPC and mask the halt.  A stopped process holds its socket and times
# out every call (c.DebugTimeout is 2s), so the very next enclave call fails.
#
# DELIBERATELY FAILS rather than skips when the chain is not running.  Restarts the node; leaves
# the chain running for the suites after it.

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

set -e

function qadenad_alias { "$qadenabin/qadenad" --home "$QADENAHOME" "$@" }

fail() {
    echo "FAIL(test_enclave_crash_recovery): $1"
    exit 1
}

chain_height() {
    curl -s -m 3 localhost:26657/status 2>/dev/null | jq -r '.result.sync_info.latest_block_height // empty'
}

h0=$(chain_height)
[ -n "$h0" ] || fail "chain is not running -- this suite refuses to skip"

# the enclave process: ego-host under SGX, the bare binary in simulation
if use_real_enclave "$qadenabin/qadenad_enclave" ; then
    enclave_pid=$(pgrep -f "ego-host.*qadenad_enclave" | head -1)
else
    enclave_pid=$(pgrep -f "qadenad_enclave --home" | head -1)
fi
[ -n "$enclave_pid" ] || fail "cannot find the enclave process"

qadenad_pid=$(pgrep -f "qadenad --home.*start" | head -1)
[ -n "$qadenad_pid" ] || fail "cannot find the qadenad process"

echo "stalling enclave pid $enclave_pid at chain height $h0"
kill -STOP "$enclave_pid" || fail "cannot SIGSTOP the enclave"

# ---- 1. the node must halt, not keep committing ----
halted=0
for i in {1..45}; do
    if ! kill -0 "$qadenad_pid" 2>/dev/null; then halted=1; break; fi
    sleep 2
done

if [ $halted -ne 1 ]; then
    kill -CONT "$enclave_pid" 2>/dev/null || true
    fail "qadenad kept running for 90s against a stalled enclave -- the fork-instead-of-halt bug is back"
fi
echo "node halted against the stalled enclave, as designed"

# a halted node must not have kept committing: whatever height it reached, it must be close to
# where the stall began (one or two in-flight blocks are legitimate)
kill -CONT "$enclave_pid" 2>/dev/null || true

# ---- 2. recovery: restart everything, reconciliation sorts the watermarks out ----
"$qadenascripts/stop_qadena.sh" --all > /dev/null 2>&1 || true
"$qadenascripts/start_qadena.sh" > /dev/null 2>&1 || fail "start_qadena.sh failed"

resumed=0
for i in {1..150}; do
    h=$(chain_height)
    if [ -n "$h" ] && [ "$h" -gt $((h0 + 3)) ]; then resumed=1; break; fi
    sleep 2
done
[ $resumed -eq 1 ] || fail "chain did not resume producing after the enclave came back"

prepared=$(qadenad_alias enclave height 2>/dev/null | grep preparedHeight | awk '{print $2}')
confirmed=$(qadenad_alias enclave height 2>/dev/null | grep confirmedHeight | awk '{print $2}')
[ -n "$prepared" ] || fail "cannot read enclave watermarks after recovery"
[ "$prepared" = "$confirmed" ] || fail "watermarks disagree after recovery: prepared=$prepared confirmed=$confirmed"

logfile="$QADENAHOME/logs/qadena.log"
if [ -f "$logfile" ] && grep -a "DIVERGED AT AN AGREED HEIGHT" "$logfile" > /dev/null; then
    fail "enclave stores diverged after crash recovery"
fi

echo "test_enclave_crash_recovery: PASSED -- halted at ~$h0 instead of forking, recovered, now at $h with watermarks $prepared/$confirmed"
