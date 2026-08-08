#!/bin/zsh
#
# Runs testscripts/regression.sh back to back for as long as the chain can pay for it.
#
# WHY THE FLOOR EXISTS, and why it is a backstop rather than a scheduled death.
#
# A run costs the treasury more than it destroys.  Measured across consecutive runs on the two-node
# testnet with every suite passing:
#
#     treasury spent per run              7,007,732 qdn
#     recovered by regression.sh's reclaim 3,200,116 qdn
#
# The rest is not destroyed either.  It has crossed from a transparent balance into ann's ENCRYPTED
# one, via the [from-transparent-amount] slot of transfer-funds in test_suspicious.sh, and
# reclaim_funds() does not yet bring it back -- see the note there.  It CAN be brought back:
# receive-funds takes a [to-transparent-amount], which converts a collected transfer into transparent
# balance, and case 10 of test_transfers.sh asserts exactly that round trip.
#
# An earlier version of this comment said the opposite -- that nothing unshields an encrypted balance,
# that ~4.5 million qdn a run left the pool for good, and that a 2 billion qdn treasury was therefore
# good for about 500 runs before only --from-genesis could recover it.  That was wrong.  Nothing here
# has to end after four days; the drain is a gap in the reclaim, not a property of the chain.
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
# Roughly seven runs of headroom, so the loop stops while the chain can still comfortably pay for
# the runs it has already started rather than part way through one.
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
