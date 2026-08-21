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
#   run_regression_continually.sh --skip a,b,c      forward --skip to every regression.sh run
#   run_regression_continually.sh --help

# get script dir
SCRIPT_DIR="${0:A:h}"

# CAPTURED BEFORE THE SOURCE, AND UNDER A NAME setup_env.sh DOES NOT USE.
#
# setup_env.sh also assigns SCRIPT_DIR="${0:A:h}", and zsh's FUNCTION_ARGZERO (on by default) makes
# $0 inside a sourced file the SOURCED file's path -- so the moment the next line runs, SCRIPT_DIR
# stops pointing at testscripts/ and points at scripts/ instead.  Anything below that reads
# "$TESTSCRIPTS_DIR/regression.sh" therefore finds nothing, silently: the --dry-run table came out empty
# and read as "no suites would run", which is the most misleading thing that output could say.
TESTSCRIPTS_DIR="${0:A:h}"

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

# FORWARDED TO EVERY regression.sh RUN.
#
# --skip is the one that matters here: enclave-rollback, enclave-crash and enclave-upgrade STOP AND
# RESTART the node by design.  That is fine when the suite owns the chain and disastrous when it does
# not -- a joining node sees the primary's RPC vanish for minutes and dies on it, and an interrupted
# crash suite can leave the enclave SIGSTOPped with the chain frozen behind it.  This loop is exactly
# the case where something else is usually using the chain, so it had to be able to say so, and until
# now it could not: it invoked regression.sh with no arguments at all.
regression_args=()
auto_skip=1
dry_run=0
manual_skip=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --max-runs) max_runs="$2"; shift 2 ;;
        --floor)    floor_qdn="$2"; shift 2 ;;
        --pause)    pause="$2"; shift 2 ;;
        --skip)     manual_skip="$2"; regression_args+=(--skip "$2"); shift 2 ;;
        --no-auto-skip) auto_skip=0; shift ;;
        --dry-run)  dry_run=1; shift ;;
        --help)
            sed -n '/^# Usage:/,/^$/p' "$0" | sed 's/^# \{0,1\}//'

            # ASK regression.sh WHAT IS SKIPPABLE; do not keep a second list here.
            #
            # It derives the names from its own run_test calls precisely so they cannot drift, and
            # its comment makes the reason plain: --skip silently ignores a name it does not match,
            # so a help text naming a suite that --skip does not recognise is worse than no help at
            # all -- the suite runs anyway and the operator believes it was skipped.  A copy of the
            # list living here would be exactly that hazard, one file further from the truth.
            if [[ -x "$TESTSCRIPTS_DIR/regression.sh" ]]; then
                "$TESTSCRIPTS_DIR/regression.sh" --help 2>/dev/null \
                    | sed -n '/^Skippable suites/,$p'
            else
                echo "Skippable suites: could not read $SCRIPT_DIR/regression.sh"
            fi

            echo ""
            echo "AUTO-SKIP.  By default this loop inspects the chain and drops what this node"
            echo "cannot run safely, so you rarely need --skip by hand:"
            echo ""
            echo "  >1/3 of bonded stake   enclave-rollback, enclave-crash and enclave-upgrade stop"
            echo "                         the node, and above a third that halts the whole chain."
            echo "  any peers              enclave-rollback takes its networked branch, which"
            echo "                         asserts against an unset \$bal_after (backlog 101)."
            echo ""
            echo "It fails closed: if the stake share cannot be read it assumes this node matters."
            echo "--no-auto-skip turns it off; --skip is still honoured and adds to the auto list."
            exit 0
            ;;
        *) echo "Unknown option: $1"; echo "try: $0 --help"; exit 1 ;;
    esac
done

# AUTO-SKIP WHAT THIS TOPOLOGY CANNOT RUN SAFELY.
#
# Three tests -- enclave-rollback, enclave-crash, enclave-upgrade -- STOP AND RESTART the node by
# design.  Whether that is safe is not a property of the test, it is a property of the CHAIN THIS
# NODE IS PART OF, and until now the operator had to know that and pass --skip by hand.  Nobody
# does, so the loop ran them on a shared fleet and the failures got read as product bugs.
#
# Two independent questions decide it, and they are asked of the chain rather than assumed:
#
#   1. WOULD STOPPING THIS NODE HALT THE CHAIN?  A validator holding more than 1/3 of bonded stake
#      is the quorum's swing vote: stop it and nothing commits until it returns.  Below 1/3 the rest
#      of the set carries on, so a self-inflicted stop costs this node only.
#
#   2. DOES THIS NODE HAVE PEERS?  enclave-rollback branches on it -- solo, it asserts the enclave
#      reverted; networked, it asserts the node re-synced back INTO the block.  Observed 2026-08-21
#      on a 4-validator fleet: the networked branch compares against $bal_after, which the script
#      never assigns, so it can only ever fail.  Skipping it here is a stopgap and NOT a fix; the
#      assertion is broken and should be repaired rather than routed around forever.
#
# --no-auto-skip turns all of this off, because a deliberate "I want to run the disruptive suite on
# this fleet, I know what it does" has to remain expressible.
topology_skips() {
    local n_peers total mine pct out=()

    n_peers=$(curl -s --max-time 5 localhost:26657/net_info 2>/dev/null | jq -r '.result.n_peers // 0' 2>/dev/null)
    [ -n "$n_peers" ] || n_peers=0

    # ASK COMETBFT WHAT THIS NODE IS, rather than matching monikers against the staking list.
    #
    # /status reports validator_info.voting_power for THIS node: 0 means it is a full node, and a
    # full node cannot halt anything by stopping itself.  An earlier version looked this node up in
    # the bonded set by moniker, which was wrong twice over -- config.toml's moniker need not equal
    # the validator's description.moniker, and a FULL NODE is absent from that list entirely, so
    # "not found" fell into the unknown branch and skipped every disruptive test on a node where
    # all of them are safe.  "I am not a validator" and "I could not tell" are different answers
    # and only the second one should fail closed.
    mine=$(curl -s --max-time 5 localhost:26657/status 2>/dev/null \
           | jq -r '.result.validator_info.voting_power // empty' 2>/dev/null)
    total=$(curl -s --max-time 5 localhost:26657/validators 2>/dev/null \
            | jq -r '[.result.validators[]?.voting_power | tonumber] | add // empty' 2>/dev/null)

    if [ -z "$mine" ]; then
        echo "  could not read this node's voting power; assuming it matters and skipping the disruptive tests" >&2
        out+=(enclave-rollback enclave-crash enclave-upgrade)
    elif [ "$mine" = "0" ]; then
        echo "  this node is a FULL NODE (voting power 0) -- stopping it cannot halt the chain" >&2
    elif [ -z "$total" ] || [ "$total" = "0" ]; then
        echo "  this node is a validator but the total voting power could not be read; assuming it matters" >&2
        out+=(enclave-rollback enclave-crash enclave-upgrade)
    else
        pct=$(echo "scale=4; $mine * 100 / $total" | bc 2>/dev/null)
        if [ "$(echo "$pct > 33.4" | bc 2>/dev/null)" = "1" ]; then
            echo "  this node holds ${pct}% of voting power -- stopping it HALTS the chain" >&2
            out+=(enclave-rollback enclave-crash enclave-upgrade)
        else
            echo "  this node holds ${pct}% of voting power -- below 1/3, a self-stop costs only this node" >&2
        fi
    fi

    if [ "$n_peers" -gt 0 ]; then
        echo "  $n_peers peer(s): enclave-rollback would take its networked branch, which asserts against an unset \$bal_after" >&2
        out+=(enclave-rollback)
    fi

    # dedupe, comma-join
    printf '%s\n' "${out[@]}" | sort -u | paste -sd, -
}

if [ $auto_skip -eq 1 ]; then
    echo "auto-skip: inspecting this node's place in the chain"
    auto=$(topology_skips)
    if [ -n "$auto" ]; then
        echo "auto-skip: skipping $auto  (override with --no-auto-skip)"
        regression_args+=(--skip "$auto")
    else
        echo "auto-skip: nothing to skip -- this node can run the full suite"
    fi
fi

# --dry-run: SAY WHAT WOULD RUN, THEN STOP.
#
# The auto-skip decision depends on the chain as it is right now -- stake share and peer count --
# so it cannot be worked out by reading the script, and until now the only way to see it was to
# start a loop that takes half an hour a lap.  This prints the same verdict the real run would use,
# per suite, and exits without touching anything.
#
# The suite names come from regression.sh's own run_test calls, the same source its --help uses, so
# a suite added or renamed there appears here without anyone updating a list.
if [ $dry_run -eq 1 ]; then
    effective="$auto"
    [ -n "$manual_skip" ] && effective="${effective:+$effective,}$manual_skip"

    echo ""
    echo "DRY RUN -- nothing will be started."
    echo ""
    if [ -n "$manual_skip" ]; then echo "  --skip (yours)   : $manual_skip"; fi
    if [ $auto_skip -eq 1 ]; then echo "  auto-skip        : ${auto:-<none>}"; else echo "  auto-skip        : disabled (--no-auto-skip)"; fi
    echo ""
    # READ regression.sh's run_test CALLS, not its help prose.  Its --help text wraps the names and
    # then explains them in sentences, so word-splitting that output harvests "and", "only", "under"
    # as if they were suites.  The run_test calls are the same source its help derives from, so this
    # cannot drift from what actually runs -- it just skips the paragraph in between.
    # while-read, NOT `for x in $(...)`: this is zsh, where an unquoted command substitution is NOT
    # word-split (no SH_WORD_SPLIT), so the for-loop form silently iterates zero or one times and
    # printed an empty table -- a dry run that lists nothing looks like "nothing would run", which
    # is the most misleading output this command could produce.
    printf "  %-22s %s\n" "SUITE" "WOULD"
    grep -oE '^[[:space:]]*run_test "[a-z0-9-]+"' "$TESTSCRIPTS_DIR/regression.sh" 2>/dev/null \
        | sed -E 's/.*run_test "([a-z0-9-]+)".*/\1/' | sort -u | while read -r label; do
        case "$label" in
            # Gated behind flags this loop never passes, so they do not run whatever --skip says.
            # Reporting them as "run" would be a lie in the one output whose job is to be believed.
            genesis-init|genesis-check|chain-start)
                printf "  %-22s -    (only with --from-genesis)\n" "$label" ;;
            sgx-build)
                printf "  %-22s -    (only with --with-sgx)\n" "$label" ;;
            enclave-upgrade)
                printf "  %-22s -    (only with --with-enclave-upgrade)\n" "$label" ;;
            *)
                if print -r -- ",$effective," | grep -q ",$label,"; then
                    printf "  %-22s SKIP\n" "$label"
                else
                    printf "  %-22s run\n" "$label"
                fi ;;
        esac
    done
    echo ""
    echo "  'recovery' is also a valid --skip name but is not a suite: it drops the key-recovery"
    echo "  cases from inside credentials, which still runs."
    exit 0
fi

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
        echo "reclaim_funds() unshields AND sweeps, so a run costs gas plus the small per-account"
        echo "float it leaves behind -- reaching this floor at all suggests the reclaim is not"
        echo "working, which is worth checking BEFORE rebuilding.  If it is genuinely spent:"
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
    "$qadenatestscripts/regression.sh" "${regression_args[@]}" > "$runlog" 2>&1
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
