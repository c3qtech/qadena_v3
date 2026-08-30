#!/bin/zsh
#
# Stop a continuous-regression loop -- here, or on a node named with --host.
#
# THE DEFAULT IS GRACEFUL, and that is the whole point of having two modes.  run_regression_
# continually.sh traps INT/TERM and sets a flag: it finishes the run in flight and then exits, so a
# plain kill of the LOOP costs at most one run's remaining time and strands nothing on the chain.
# Killing a suite part way through is exactly what leaves state behind -- a half-created wallet, a
# credential nobody reclaims, a SIGSTOPped enclave -- and those turn into failures in the NEXT run
# that look like chain bugs.
#
#   stop_regression.sh                     stop the loop, wait for the run in flight to finish
#   stop_regression.sh --immediate         also END the run in flight now (SIGTERM, then SIGKILL)
#   stop_regression.sh --host m1           do either of those over ssh
#
# --immediate is named for the convention already in the tree: nth_node_bringup.sh and
# upgrade_fleet.sh spell this --quiesce / --quiesce-immediate, where "quiesce" is the base action
# and the suffix opts into not waiting.  Here stopping IS the action, so the suffix stands alone.
#
# ---------------------------------------------------------------------------------------------
# THE TRAPS THIS ENCODES, each of which has bitten before:
#
#   1. KILL THE LOOP BY PID, NEVER BY PATTERN.  `pkill -f run_regression_continually` matches the
#      ssh command that carries the name, so over ssh it kills the session doing the killing and
#      the loop survives.  Every pgrep pattern here is bracket-classed for the same reason.
#
#   2. SIGTERM BEFORE SIGKILL, and not out of politeness.  test_enclave_crash_recovery.sh SIGSTOPs
#      the enclave and resumes it from a `trap ... EXIT INT TERM`.  SIGTERM lets that trap run so
#      the test resumes the enclave itself; SIGKILL skips it and strands a STOPPED enclave with the
#      node frozen behind it -- manufacturing the very wedge --immediate exists to avoid.
#
#   3. THE SIGCONT BACKSTOP is what makes --immediate safe to offer at all.  If the trap did not
#      run -- SIGKILL, or a suite that never installed one -- the enclave is still SIGSTOPped and
#      the node is frozen behind a process table that looks perfectly healthy.  A SIGCONT to a
#      process that was never stopped costs nothing, so it is unconditional.
#
#   4. `pgrep -c` PRINTS the count and EXITS NON-ZERO when that count is zero.  `pgrep -cf x || echo 0`
#      therefore emits "0\n0" and the arithmetic downstream dies with "operator expected" -- and it
#      fails precisely when nothing is running, which is the normal case here.  Hence `; true`
#      and `head -1` on every count.
#
#   4b. THIS SCRIPT'S OWN NAME ENDS IN "_regression.sh", so a bare [r]egression\.sh pattern
#      matches the stopper itself -- it would see a run in flight that is really just this process,
#      wait out the timeout and exit 1 having stopped everything correctly.  The pattern is anchored
#      on a path separator so it cannot.
#
#   5. A BARE regression.sh WITH NO LOOP ABOVE IT is a real state (someone ran one by hand, or the
#      loop was killed and its run left behind).  Reported and handled rather than ignored: the
#      default waits for it, --immediate ends it.

set -u

ME="${0:t}"
HOST=""
IMMEDIATE=0
WAIT_MIN=60

while [[ $# -gt 0 ]]; do
    case "$1" in
        --immediate) IMMEDIATE=1; shift ;;
        --host)      HOST="$2"; shift 2 ;;
        --timeout)   WAIT_MIN="$2"; shift 2 ;;
        --help)
            print "Usage: $ME [--immediate] [--host [user@]host] [--timeout MIN]"
            print ""
            print "  Stops a continuous-regression loop (run_regression_continually.sh)."
            print ""
            print "  (default)     SIGTERM the loop by PID and WAIT for the run in flight to"
            print "                finish.  The loop traps TERM, so it stops after that run"
            print "                rather than mid-suite -- nothing is stranded on the chain."
            print "  --immediate   as above, but END the run in flight NOW: SIGTERM the suite,"
            print "                then SIGKILL if it will not go, then SIGCONT anything left"
            print "                STOPPED (a killed enclave-crash test freezes the node)."
            print "  --host        do it on that node over ssh instead of here."
            print "  --timeout     minutes to wait for the in-flight run (default $WAIT_MIN)."
            print ""
            print "  Exit 0 when nothing is left running, 1 otherwise."
            exit 0 ;;
        *) print -u2 "$ME: unknown option $1  (--help)"; exit 1 ;;
    esac
done

[[ "$WAIT_MIN" == <-> ]] || { print -u2 "$ME: --timeout takes minutes, got \"$WAIT_MIN\""; exit 1 }

# ONE PLACE THAT KNOWS WHETHER THIS IS LOCAL OR REMOTE, so every probe and signal below reads the
# same either way.  BatchMode so a host that wants a password fails now instead of hanging.
rsh() {
    if [[ -n "$HOST" ]]; then
        ssh -o ConnectTimeout=10 -o BatchMode=yes "$HOST" "$1"
    else
        zsh -c "$1"
    fi
}

WHERE="${HOST:-this host}"

# Trap 4: `; true` and head -1, or a zero count arrives as two lines and breaks the comparison.
count_of() {   # bracket-classed pattern
    rsh "pgrep -cf '$1' 2>/dev/null; true" 2>/dev/null | tr -d '[:space:]' | head -1
}

loop_count() { count_of '[r]un_regression_continually' }
# ANCHORED ON A PATH SEPARATOR, because this script's own name ends in "_regression.sh" and a
# bare [r]egression\.sh matches it -- so the check would see itself, report a run in flight forever,
# and never exit 0.  Requiring "/" or a space before it matches ".../testscripts/regression.sh" and
# "zsh regression.sh" while excluding "stop_regression.sh" (preceded by "_").
run_count()  { count_of '(^|[/ ])[r]egression\.sh' }

if [[ -n "$HOST" ]]; then
    rsh 'true' >/dev/null 2>&1 || { print -u2 "$ME: cannot ssh to $HOST"; exit 1 }
fi

print "$ME: looking for a continuous-regression loop on $WHERE"

# Trap 1: the LOOP is signalled by PID.  Collected before anything is killed so the report and the
# action describe the same set.
loop_pids=$(rsh 'pgrep -f "[r]un_regression_continually" 2>/dev/null; true' 2>/dev/null | tr '\n' ' ')

if [[ -n "${loop_pids// /}" ]]; then
    print "$ME: stopping the loop (pids: ${loop_pids% })"
    for p in ${=loop_pids}; do
        rsh "kill $p 2>/dev/null; true" >/dev/null 2>&1
    done
    sleep 3
else
    print "$ME: no continuous-regression loop is running"
fi

# Trap 5: a suite can be running with no loop above it, and that still has to be dealt with.
n=$(run_count)
if [[ "${n:-0}" -eq 0 ]]; then
    print "$ME: no regression run in flight"
    print "$ME: done -- nothing is running on $WHERE"
    exit 0
fi

if [[ $IMMEDIATE -eq 0 ]]; then
    print "$ME: waiting up to ${WAIT_MIN}m for the run in flight to finish (it stops cleanly after this run)"
    print "$ME: pass --immediate to end it now instead"
    typeset -i i=0
    while (( i < WAIT_MIN * 2 )); do
        n=$(run_count)
        [[ "${n:-0}" -eq 0 ]] && break
        sleep 30
        (( ++i ))
    done
else
    # Trap 2: SIGTERM first, so a suite with an EXIT/INT/TERM trap gets to run it.
    print "$ME: --immediate: ending the run in flight now (SIGTERM, then SIGKILL)"
    rsh "pkill -TERM -f '(^|[/ ])[r]egression\.sh' 2>/dev/null; true" >/dev/null 2>&1
    typeset -i i=0
    while (( i < 10 )); do
        n=$(run_count)
        [[ "${n:-0}" -eq 0 ]] && break
        sleep 2
        (( ++i ))
    done
    if [[ "${n:-0}" -ne 0 ]]; then
        print "$ME: it did not exit on SIGTERM; SIGKILL"
        rsh "pkill -KILL -f '(^|[/ ])[r]egression\.sh' 2>/dev/null; true" >/dev/null 2>&1
        sleep 2
        n=$(run_count)
    fi

    # Trap 3: unconditional, because the expensive case is the one where we cannot tell.
    stopped=$(rsh 'ps -eo stat=,pid=,comm= 2>/dev/null | awk "\$1 ~ /^T/ && \$3 ~ /qadenad|enclave/ {print \$2}" | tr "\n" " "; true' 2>/dev/null | tr -d '\r')
    if [[ -n "${stopped// /}" ]]; then
        print "$ME: resuming STOPPED enclave process(es): ${stopped% }  (a killed test left them halted)"
        rsh "kill -CONT ${stopped} 2>/dev/null; true" >/dev/null 2>&1
    fi
fi

# WHAT IS ACTUALLY LEFT, asked fresh rather than inferred from the loops above.
lc=$(loop_count)
rc=$(run_count)
if [[ "${lc:-0}" -ne 0 || "${rc:-0}" -ne 0 ]]; then
    print -u2 "$ME: FAILED: still running on $WHERE (loop=$lc in-flight=$rc)"
    print -u2 "$ME:         stop them BY PID, or re-run with --immediate."
    exit 1
fi

print "$ME: done -- nothing is running on $WHERE"
exit 0
