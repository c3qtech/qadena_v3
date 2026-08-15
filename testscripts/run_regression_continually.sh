#!/bin/zsh
#
# Runs testscripts/regression.sh back to back for as long as the chain can pay for it.
#
# WHY THE FLOOR EXISTS, and why it is a backstop rather than a scheduled death.
#
# A RUN CONSUMES GAS, essentially and by design.  Everything else it moves comes back.
#
# reclaim_funds() in regression.sh sweeps both halves, in one pass and in the right order: it
# UNSHIELDS FIRST -- draining any stranded queue entries, then moving each account's encrypted
# surplus out through an ephemeral wallet (ann-eph2, victor-eph1) -- and only then sweeps the
# transparent balances into the treasury.  Doing it in that order is what stops the unshielded funds
# sitting a run behind the sweep that is supposed to collect them.
#
# What a run therefore costs the treasury is gas, plus the deliberately small reserves left behind:
# a 1000 qdn float per account so the next run has something to pay gas with, and whatever sits
# under a suite's own assertion thresholds.  It is not a per-run drain of millions.
#
# THE FIGURES THAT USED TO BE HERE -- 7,007,732 qdn spent per run against 3,200,116 reclaimed -- WERE
# MEASURED BEFORE THE UNSHIELD EXISTED, when reclaim_funds() moved transparent balance only and the
# remainder stayed in ann's encrypted balance.  They no longer describe this loop, and quoting them
# makes the suite look far more expensive than it is.  Anyone who wants a current number should
# measure one rather than trust a figure from a different implementation; that is why none is quoted
# here now.
#
# (An older version of the comment was wrong in the other direction as well, claiming an encrypted
# balance could never be unshielded and that a 2 billion qdn treasury was good for ~500 runs before
# only --from-genesis could recover it.  Both readings were an artefact of a reclaim gap that has
# since been closed, not a property of the chain.)
#
# The floor stays regardless, because a treasury that DOES run down takes every suite with it at
# once, and a wall of failures on insufficient funds reads as a catastrophic regression rather than
# an empty wallet.  Stopping and saying so is worth more than looping into that.  Rebuilding remains
# a deliberate act -- regression.sh --from-genesis -- because it destroys the chain, and that is not
# something a loop should decide at 3am.
#
# Usage:
#   run_regression_continually.sh                    loop until the treasury floor is hit
#   run_regression_continually.sh --max-runs N       stop after N runs as well
#   run_regression_continually.sh --floor QDN        treasury floor (default 50000000)
#   run_regression_continually.sh --pause SECONDS    wait between runs (default 0, back to back)
#   run_regression_continually.sh --help

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

# NO `set -e`.  A failing run is the thing this script exists to record, not a reason to stop.
# regression.sh returns non-zero whenever any suite fails, which is expected input here.

function qadenad_alias { "$qadenabin/qadenad" --home "$QADENAHOME" "$@" }

max_runs=0
pause=0
# A floor with a lot of headroom, deliberately.  It used to be justified as "roughly seven runs",
# which was 50000000 divided by a per-run cost that no longer applies now that reclaim_funds()
# unshields -- see the header.  Against gas alone this is very many runs, and that is fine: the
# floor is a backstop against an unnoticed reclaim regression, not a budget.  Its job is to stop the
# loop while the chain can still comfortably pay, so keep it generous rather than tuned.
floor_qdn=50000000

while [[ $# -gt 0 ]]; do
    case "$1" in
        --max-runs) max_runs="$2"; shift 2 ;;
        --floor)    floor_qdn="$2"; shift 2 ;;
        --pause)    pause="$2"; shift 2 ;;
        --help)
            sed -n '/^# Usage:/,/^$/p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) echo "Unknown option: $1"; echo "try: $0 --help"; exit 1 ;;
    esac
done

archive="$qadenabuild/logs/regression-history"
mkdir -p "$archive"
history_file="$archive/history.tsv"
[ -f "$history_file" ] || printf 'started\tended\trun\tresult\tfailed\ttreasury_qdn\n' > "$history_file"

treasury_qdn() {
    local addr amt
    addr=$(qadenad_alias keys show treasury -a --keyring-backend test 2>/dev/null) || { echo ""; return; }
    [ -n "$addr" ] || { echo ""; return; }
    amt=$(qadenad_alias query bank balances "$addr" --output json 2>/dev/null \
        | jq -r '.balances[] | select(.denom=="aqdn") | .amount' 2>/dev/null)
    [ -n "$amt" ] || { echo ""; return; }
    python3 -c "print(int('$amt') // 10**18)"
}

# Stop cleanly rather than leaving a half-finished run looking like a crash.  The current run is not
# interrupted -- killing a suite part way through is exactly what strands state on the chain.
stop_requested=0
trap 'stop_requested=1; echo ""; echo "stop requested; finishing the current run first"' INT TERM

run=0
while true; do
    if [ "$stop_requested" -eq 1 ]; then
        echo "stopping as requested after $run run(s)"
        break
    fi
    if [ "$max_runs" -gt 0 ] && [ "$run" -ge "$max_runs" ]; then
        echo "reached --max-runs $max_runs"
        break
    fi

    have=$(treasury_qdn)
    if [ -z "$have" ]; then
        echo "could not read the treasury balance -- is the chain up?  stopping rather than looping blind."
        exit 1
    fi
    if [ "$have" -lt "$floor_qdn" ] 2>/dev/null; then
        echo ""
        echo "======================================================================"
        echo "TREASURY FLOOR REACHED: ${have}qdn left, floor is ${floor_qdn}qdn"
        echo "======================================================================"
        echo "reclaim_funds() returns the transparent balance but not what crossed into ann's"
        echo "encrypted one, so the pool drains slowly.  That is recoverable (see reclaim_funds),"
        echo "but until it is, rebuilding is the way back:"
        echo ""
        echo "    testscripts/regression.sh --from-genesis"
        echo ""
        echo "That DELETES $QADENAHOME.  $run run(s) completed; history in $history_file"
        exit 2
    fi

    run=$((run + 1))
    started=$(date -u +%FT%TZ)
    stamp=$(date -u +%Y%m%dT%H%M%SZ)
    echo ""
    echo "######################################################################"
    echo "# run $run  started $started  treasury ${have}qdn"
    echo "######################################################################"

    runlog="$archive/run-$stamp.log"
    "$qadenatestscripts/regression.sh" > "$runlog" 2>&1
    rc=$?
    ended=$(date -u +%FT%TZ)

    # The summary block is the useful part; the per-suite detail stays in logs/regression, which the
    # NEXT run overwrites -- so a failing run's suite logs are copied out before that can happen.
    sed -n '/^REGRESSION SUMMARY/,$p' "$runlog"
    failed=$(sed -n 's/^  \([0-9][0-9]*\) of [0-9][0-9]* SUITES FAILED$/\1/p' "$runlog" | tail -1)
    [ -n "$failed" ] || failed=0

    if [ "$rc" -ne 0 ]; then
        faildir="$archive/failed-$stamp"
        mkdir -p "$faildir"
        cp "$qadenabuild/logs/regression/"*.log "$faildir/" 2>/dev/null
        echo "run $run FAILED ($failed suite(s)); suite logs kept in $faildir"
        result=FAIL
    else
        result=PASS
    fi

    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$started" "$ended" "$run" "$result" "$failed" "$(treasury_qdn)" \
        >> "$history_file"

    [ "$pause" -gt 0 ] 2>/dev/null && sleep "$pause"
done

echo ""
echo "history: $history_file"
