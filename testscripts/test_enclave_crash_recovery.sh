#!/bin/zsh
#
# Fault injection reproducing the 2026-08-09 incident shape: the enclave stops responding
# mid-run.  The node must HALT (haltOnEnclaveFailure) rather than commit enclave-less blocks --
# on the real network the old behaviour finalised 31,675 blocks a healthy peer had rejected --
# and after the enclave returns, a restart must reconcile and resume.
#
# The stall is injected with SIGSTOP, not SIGKILL, for two reasons: it matches the incident (the
# enclave hung inside an OOM before dying), and it isolates the property under test -- the
# WATCHDOG's hung-enclave detection.  A SIGKILLed enclave exercises a different, faster path now:
# qadenad supervises its spawned enclave and exits immediately with a named cause when the child
# DIES, no watchdog involved.  A stopped process is alive-but-silent, which only the watchdog
# can call.
#
# HOW THE HALT ARRIVES.  Execution-path enclave calls carry NO deadline (the height-34,025 fix),
# so a stopped enclave does not fail the next call -- it blocks it, and the chain freezes at once
# with nothing yet in the log.  The WATCHDOG (x/qadena/keeper/enclave_call_context.go) is what
# turns that freeze into the named halt: it probes SayHello off the consensus path, and once the
# enclave has been silent past QADENA_ENCLAVE_HEALTH_GRACE (default 2m) it cancels the shared
# alive-context, every blocked call unblocks, and haltOnEnclaveFailure panics with the cause.
# Freezing promptly and halting later are therefore SEPARATE properties, asserted separately
# below.  (An earlier version of this comment claimed c.DebugTimeout failed the very next call;
# that was true before the fork fix removed the deadline, and this suite failed silently for as
# long as the comment outlived the mechanism.)
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

# RESUME ON EVERY EXIT PATH.  The SIGCONT used to sit after the assertions, so any `fail` between
# the STOP and there left the enclave in state T for good -- not a lost test but a wedged machine:
# with no deadline on execution calls the chain blocks forever, and every suite after this one
# hangs too.  Observed 2026-08-16: one failed assertion, enclave stopped for 2.5 hours, the whole
# regression stalled behind it.  The trap fires on normal exit, on `fail`, and on interruption.
# RESUMING IS NOT RECOVERING, and that distinction cost 29 consecutive rounds on 2026-08-29.
#
# The halt this suite provokes kills CONSENSUS but leaves the PROCESS ALIVE, so SIGCONT alone
# gives back a node that answers RPC and will never commit another block.  The restart that fixes
# that sits after the assertions, so any `fail` skipped it -- and every later round then found a
# chain already frozen, with its halt message written before that round's log offset.  One failure
# poisoned the soak: 118 passes, then 29 identical 185s timeouts, the node down the whole time.
#
# So the trap RESTARTS the node, not just the enclave.  Idempotent on the happy path: the explicit
# restart below leaves nothing for it to do, and start_qadena.sh is a no-op against a running node.
crash_cleanup() {
    as_enclave_owner kill -CONT "$enclave_pid" 2>/dev/null || true

    # IS IT ADVANCING -- not "is it answering".  A halted node keeps serving RPC and reports a
    # stuck height forever, so an answering check would call the exact state this exists to fix
    # healthy.  Two reads, four seconds apart.
    local a b
    a=$(chain_height 2>/dev/null); sleep 4; b=$(chain_height 2>/dev/null)
    if [ -n "$a" ] && [ -n "$b" ] && [ "$b" != "$a" ]; then
        return 0    # advancing: the happy path already restarted it, or it never halted
    fi

    echo "crash_cleanup: chain is not advancing ($a -> $b) -- restarting the node"
    # Same short grace the explicit restart uses, so a following round's watchdog fires promptly
    # rather than waiting out the 2m default.
    export QADENA_ENCLAVE_HEALTH_GRACE=15s
    "$qadenascripts/stop_qadena.sh" --all >/dev/null 2>&1 || true
    "$qadenascripts/start_qadena.sh" >/dev/null 2>&1 || \
        echo "crash_cleanup: WARNING: start_qadena.sh failed -- the node is DOWN and later suites will fail against it"
}
trap crash_cleanup EXIT INT TERM

# The log is cumulative across runs -- nothing rotates it -- so a halt message from a PREVIOUS
# cycle of this very suite would satisfy the poll below instantly and falsely.  Everything this
# run asserts must come from lines written after this point.
logfile="$QADENAHOME/logs/qadena.log"
log_start=$(wc -l < "$logfile" 2>/dev/null || echo 0)

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

# and the halt must be the one we mean, not some unrelated stall.
#
# POLLED, not grepped once: the freeze is immediate (the blocked EndBlock stops commits within a
# block) but the NAMED halt waits for the watchdog's grace.  The ceiling covers the 2m default
# plus margin; a node started with a shorter QADENA_ENCLAVE_HEALTH_GRACE (see the restart below)
# exits this loop as soon as the message lands.
# TWO CORRECT OUTCOMES, and the suite must accept both.
#
#   halt      haltOnEnclaveFailure panics; consensus dies, the PROCESS STAYS UP.  This is the
#             common path, because a stalled enclave usually has a call in flight to cancel.
#
#   backstop  the watchdog declared the enclave dead but the cancellation reached NO IN-FLIGHT
#             CALL, so haltOnEnclaveFailure never ran and the node is wedged rather than halted.
#             enclave_call_context.go says so in as many words and exits non-zero on purpose,
#             "so the supervisor can restart it".  Equally correct, and not rare: whether a call
#             is in flight when SIGSTOP lands is a race, which is why this suite failed exactly
#             once in 82 soak rounds (2026-08-28) and took the fleet down with it.
#
# Accepting only the first reported the second as a bug in the node, when the node had in fact
# detected a worse condition and said so.  What must still fail is NEITHER appearing.
halted=0
halt_kind=""
for i in {1..90}; do
    if [ -f "$logfile" ]; then
        tailed=$(tail -n "+$((log_start + 1))" "$logfile")
        if print -r -- "$tailed" | grep -aq "halting rather than committing a block without the enclave's state"; then
            halted=1; halt_kind="halt (haltOnEnclaveFailure ran)"; break
        fi
        if print -r -- "$tailed" | grep -aq "wedged rather than halted"; then
            halted=1; halt_kind="backstop (no in-flight call to cancel; the node exited for the supervisor)"; break
        fi
    fi
    sleep 2
done
[ $halted -eq 1 ] || fail "the chain stopped, but NEITHER halt message appeared in 180s -- not haltOnEnclaveFailure's, and not the wedged-node backstop's.  The watchdog did not declare the enclave dead at all, which is the case this suite exists to catch."
echo "chain halted at $h_final ($advanced block(s) after the stall began) -- $halt_kind"

as_enclave_owner kill -CONT "$enclave_pid" 2>/dev/null || true

# ---- 2. recovery: restart everything, reconciliation sorts the watermarks out ----
"$qadenascripts/stop_qadena.sh" --all > /dev/null 2>&1 || true

# The restarted node gets a SHORT watchdog grace, inherited through start_qadena.sh's environment.
# It cannot speed up THIS run -- the node under test was started before this suite ran -- but the
# chain it leaves behind is the one the next cycle stalls, so every cycle after the first waits
# ~15s for the named halt instead of the 2m production default.
export QADENA_ENCLAVE_HEALTH_GRACE=15s
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
# AND SAMPLED UNTIL THEY SETTLE, because one invocation is still not one instant on a chain that
# is producing.  prepared LEADING confirmed by one is not a disagreement, it is the normal window
# between the enclave's EndBlock (which prepares H) and the chain's Commit (which confirms it).  A
# sample that lands inside that window sees prepared=H confirmed=H-1 on a perfectly healthy node.
#
# Observed on real SGX, where the window is widest: prepared=1057 confirmed=1056, on a run whose
# halt and recovery had both worked.  The Mac and ARM passed the same code by being fast enough to
# miss the window, which is the definition of a flaky assertion rather than a finding.
#
# So: poll for equality, which a live chain reaches every block; fail only if they never converge.
# confirmed AHEAD of prepared is still failed IMMEDIATELY -- that one is impossible by
# construction, so it means something real rather than a badly timed look.
prepared=""; confirmed=""; settled=0
for i in {1..20}; do
    watermarks=$(qadenad_alias enclave height 2>/dev/null)
    prepared=$(print -r -- "$watermarks" | grep preparedHeight | awk '{print $2}')
    confirmed=$(print -r -- "$watermarks" | grep confirmedHeight | awk '{print $2}')
    [ -n "$prepared" ] || { sleep 1; continue }
    if [ -n "$confirmed" ] && [ "$confirmed" -gt "$prepared" ] 2>/dev/null; then
        fail "enclave reports confirmed AHEAD of prepared (confirmed=$confirmed prepared=$prepared), which cannot happen: confirming a height follows preparing it"
    fi
    [ "$prepared" = "$confirmed" ] && { settled=1; break }
    sleep 1
done
[ -n "$prepared" ] || fail "cannot read enclave watermarks after recovery"
[ $settled -eq 1 ] || fail "watermarks disagree after recovery: prepared=$prepared confirmed=$confirmed
Both were read from a SINGLE enclave height call, so this is a real disagreement rather than two
samples taken a block apart."

logfile="$QADENAHOME/logs/qadena.log"
# Anchored to THIS run's lines, like the halt poll above: the log is cumulative, and a DIVERGED
# from an earlier suite (or an earlier cycle of this one) must not fail a recovery that was clean.
if [ -f "$logfile" ] && tail -n "+$((log_start + 1))" "$logfile" | grep -aq "DIVERGED AT AN AGREED HEIGHT"; then
    fail "enclave stores diverged after crash recovery"
fi

echo "test_enclave_crash_recovery: PASSED -- halted at ~$h0 instead of forking, recovered, now at $h with watermarks $prepared/$confirmed"
