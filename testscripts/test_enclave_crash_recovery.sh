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

echo "stalling enclave pid $enclave_pid at chain height $h0"
as_enclave_owner kill -STOP "$enclave_pid" || fail "cannot SIGSTOP the enclave"

# ---- 1. the node must stop COMMITTING -- which is not the same as the process exiting ----
#
# haltOnEnclaveFailure panics.  That panic propagates into CometBFT's consensus receiveRoutine,
# whose deferred recover logs "CONSENSUS FAILURE!!!", stops the WAL, and returns -- killing the
# consensus reactor while leaving the PROCESS ALIVE, still serving RPC.  That is exactly what
# .140 did during the 2026-08-09 incident: up for a day with a dead reactor.
#
# So the safety property to assert is that the chain STOPS ADVANCING, not that qadenad exits.
# An earlier version of this suite checked for process death and failed against entirely correct
# behaviour -- a false alarm that would have sent someone hunting a bug that was not there.
frozen_at=""
for i in {1..30}; do
    sleep 2
    h=$(chain_height)
    [ -n "$h" ] || continue          # RPC may blip; absence is not progress
    if [ -n "$frozen_at" ] && [ "$h" = "$frozen_at" ]; then
        # two consecutive reads at the same height, well past the 1.5s block time
        break
    fi
    frozen_at="$h"
done

[ -n "$frozen_at" ] || fail "could not read the chain height while the enclave was stalled"

h_final=$(chain_height)
[ "$h_final" = "$frozen_at" ] || fail "chain is STILL ADVANCING against a stalled enclave ($frozen_at -> $h_final) -- the fork-instead-of-halt bug is back"

# it must have stopped near where the stall began, not run on for dozens of blocks
advanced=$((h_final - h0))
[ "$advanced" -le 5 ] || fail "chain advanced $advanced blocks after the enclave stalled before stopping; expected it to halt within a block or two"

# and the halt must be the one we mean, not some unrelated stall
logfile="$QADENAHOME/logs/qadena.log"
if [ -f "$logfile" ]; then
    grep -a "halting rather than committing a block without the enclave's state" "$logfile" > /dev/null \
        || fail "the chain stopped, but haltOnEnclaveFailure's message is not in the log -- it stopped for some other reason"
fi
echo "chain halted at $h_final ($advanced block(s) after the stall began), with haltOnEnclaveFailure in the log"

as_enclave_owner kill -CONT "$enclave_pid" 2>/dev/null || true

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

# ONE invocation, both watermarks parsed from it.  Two separate `enclave height` calls sample the
# enclave at two different instants, and on a chain that is producing again the block in between
# moves the watermarks -- so this used to report a "disagreement" the enclave never held.
#
# The tell was that it reported confirmed AHEAD of prepared (e.g. prepared=13420 confirmed=13421),
# which the product cannot produce: preparing height H happens in the enclave's EndBlock and
# confirming H happens after the chain's Commit, so confirmed can lag prepared but never lead it.
# A watermark pair that is impossible by construction is a measurement artefact, not a finding.
#
# Reported from a parallel ARM run; the two-call structure is the whole cause.
watermarks=$(qadenad_alias enclave height 2>/dev/null)
prepared=$(print -r -- "$watermarks" | grep preparedHeight | awk '{print $2}')
confirmed=$(print -r -- "$watermarks" | grep confirmedHeight | awk '{print $2}')
[ -n "$prepared" ] || fail "cannot read enclave watermarks after recovery"
[ "$prepared" = "$confirmed" ] || fail "watermarks disagree after recovery: prepared=$prepared confirmed=$confirmed
Both were read from a SINGLE enclave height call, so this is a real disagreement rather than two
samples taken a block apart."

logfile="$QADENAHOME/logs/qadena.log"
if [ -f "$logfile" ] && grep -a "DIVERGED AT AN AGREED HEIGHT" "$logfile" > /dev/null; then
    fail "enclave stores diverged after crash recovery"
fi

echo "test_enclave_crash_recovery: PASSED -- halted at ~$h0 instead of forking, recovered, now at $h with watermarks $prepared/$confirmed"
