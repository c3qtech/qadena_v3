#!/bin/zsh
#
# Runs the whole regression suite and reports a summary.
#
# Every test below is IDEMPOTENT -- safe to run repeatedly against the same chain.  They achieve
# that in different ways depending on what the module allows: delta assertions rather than absolute
# balances (transfers), per-run unique ids and content (dsvs), fresh deploys (evm, wasm), top-up
# only when short (suspicious), and end-state guards rather than "did I run before" (prerequisites).
#
# DELIBERATELY EXCLUDED BY DEFAULT: update_credentials.sh.  It is single-shot -- its claim codes are
# single-use and cases 1/2/5 consume rate-limit windows -- so it cannot be re-run against the same
# chain without editing the codes at the top.  Pass --with-credentials to include it on a chain that
# has never run it.
#
# Usage:
#   regression.sh                     run the repeatable suite
#   regression.sh --with-setup        run setup.sh first (slow; needed on a fresh chain)
#   regression.sh --with-credentials  also run the single-shot update_credentials.sh, last
#   regression.sh --stop-on-fail      stop at the first failure instead of running everything

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

# NOTE: no `set -e` here.  This script's job is to run every test and report, so a failing test must
# not abort the runner.  Each test script has its own set -e.

function qadenad_alias { "$qadenabin/qadenad" --home "$QADENAHOME" "$@" }

with_setup=false
with_credentials=false
stop_on_fail=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --with-setup)       with_setup=true; shift ;;
        --with-credentials) with_credentials=true; shift ;;
        --stop-on-fail)     stop_on_fail=true; shift ;;
        --help)
            echo "Usage: $0 [--with-setup] [--with-credentials] [--stop-on-fail]"
            echo "  --with-setup        run setup.sh first (slow; needed on a fresh chain)"
            echo "  --with-credentials  also run the single-shot update_credentials.sh"
            echo "  --stop-on-fail      stop at the first failure"
            exit 0
            ;;
        *) echo "Unknown option: $1"; echo "try: $0 --help"; exit 1 ;;
    esac
done

logdir="$qadenabuild/logs/regression"
mkdir -p "$logdir"

names=()
results=()
seconds=()
failed=0

# run_test <label> <script> [args...]
run_test() {
    local label="$1"; shift
    local script="$1"; shift
    local logfile="$logdir/${label}.log"
    local start end rc

    echo ""
    echo "======================================================================"
    echo ">>> $label"
    echo "======================================================================"

    start=$(date +%s)
    "$script" "$@" > "$logfile" 2>&1
    rc=$?
    end=$(date +%s)

    names+=("$label")
    seconds+=($((end - start)))

    if [ $rc -eq 0 ]; then
        results+=("PASS")
        echo "PASS  ($((end - start))s)  -> $logfile"
    else
        results+=("FAIL")
        failed=$((failed + 1))
        echo "FAIL  ($((end - start))s)  -> $logfile"
        echo "--- last 15 lines ---"
        tail -15 "$logfile" | sed 's/^/    /'
        echo "---------------------"
        if [ "$stop_on_fail" = "true" ]; then
            echo ""
            echo "stopping at first failure (--stop-on-fail)"
            summarize
            exit 1
        fi
    fi
}

summarize() {
    echo ""
    echo "======================================================================"
    echo "REGRESSION SUMMARY"
    echo "======================================================================"
    local i=1
    while [ $i -le ${#names[@]} ]; do
        printf "  %-6s %-28s %4ss\n" "${results[$i]}" "${names[$i]}" "${seconds[$i]}"
        i=$((i + 1))
    done
    echo "----------------------------------------------------------------------"
    if [ $failed -eq 0 ]; then
        echo "  ALL ${#names[@]} SUITES PASSED"
    else
        echo "  $failed of ${#names[@]} SUITES FAILED"
    fi
    echo "======================================================================"
    echo "logs: $logdir"
}

echo "======================================================================"
echo "QADENA REGRESSION SUITE"
echo "======================================================================"

# The chain has to be up before anything else -- every test below assumes it, and failing here
# gives one clear message instead of the same error repeated six times.
if ! qadenad_alias status > /dev/null 2>&1; then
    echo "FAILED: chain is not reachable."
    echo "  start it with:  scripts/start_qadena.sh"
    echo "  on a fresh genesis:  buildscripts/init.sh --advertise-ip-address <ip>"
    exit 1
fi
echo "chain up at height $(qadenad_alias status 2>/dev/null | jq -r '.sync_info.latest_block_height' 2>/dev/null || echo '?')"

# Providers, oracles and the create-wallet sponsor are no longer genesis accounts, so they must be
# onboarded before anything can transact.  This is idempotent and cheap when already done.
run_test "prerequisites" "$qadenatestscripts/setup_prerequisites.sh"

if [ "$with_setup" = "true" ]; then
    run_test "setup" "$qadenatestscripts/setup.sh"
else
    # setup.sh is slow, so it is opt-in -- but the tests need its users, so check rather than
    # letting each one fail separately with its own confusing message
    if ! qadenad_alias keys show al -a --keyring-backend test > /dev/null 2>&1; then
        echo ""
        echo "FAILED: the test users do not exist (al is missing)."
        echo "  run:  $0 --with-setup"
        exit 1
    fi
    echo "test users present (skipping setup.sh; use --with-setup to force)"
fi

run_test "pricefeed"   "$qadenatestscripts/test_pricefeed.sh"
run_test "transfers"   "$qadenatestscripts/test_transfers.sh"
run_test "suspicious"  "$qadenatestscripts/test_suspicious.sh"
run_test "dsvs"        "$qadenatestscripts/test_dsvs.sh"
run_test "wasm"        "$qadenatestscripts/test_wasm.sh"
run_test "evm"         "$qadenatestscripts/test_evm.sh"

if [ "$with_credentials" = "true" ]; then
    # last, because it mutates identities the other tests read -- it removes al's email credential,
    # renames jill, and puts al/jill/dory inside their update cool-down windows
    run_test "update_credentials" "$qadenatestscripts/update_credentials.sh"
fi

summarize
[ $failed -eq 0 ]
