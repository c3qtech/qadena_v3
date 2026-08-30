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
#   run_regression_continually.sh --dry-run          say what this node would run, then stop
#   run_regression_continually.sh --summary          per-suite totals over every archived run, then stop
#   run_regression_continually.sh --clear-results    delete the archived results and start the history over
#                                                    (asks first; -y / --yes skips the prompt)
#   run_regression_continually.sh --help
#
# --summary reads the archived per-run JSON, so it reports on a loop that is ALREADY RUNNING (or one
# that finished days ago) without starting or disturbing anything.  regression.sh writes that JSON;
# the printed summary table is for humans and nothing parses it.

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
# --skip is the one that matters here: enclave-rollback and enclave-crash STOP AND
# RESTART the node by design.  That is fine when the suite owns the chain and disastrous when it does
# not -- a joining node sees the primary's RPC vanish for minutes and dies on it, and an interrupted
# crash suite can leave the enclave SIGSTOPped with the chain frozen behind it.  This loop is exactly
# the case where something else is usually using the chain, so it had to be able to say so, and until
# now it could not: it invoked regression.sh with no arguments at all.
regression_args=()
auto_skip=1
dry_run=0
summary_only=0
clear_results=0
assume_yes=0
manual_skip=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --max-runs) max_runs="$2"; shift 2 ;;
        --floor)    floor_qdn="$2"; shift 2 ;;
        --pause)    pause="$2"; shift 2 ;;
        --skip)     manual_skip="$2"; shift 2 ;;   # merged with the auto list below, see there
        --no-auto-skip) auto_skip=0; shift ;;
        --dry-run)  dry_run=1; shift ;;
        --summary)  summary_only=1; shift ;;
        --clear-results) clear_results=1; shift ;;
        --yes|-y)   assume_yes=1; shift ;;
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
            echo "  >1/3 of bonded stake   enclave-rollback and enclave-crash stop"
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
# Two tests -- enclave-rollback and enclave-crash -- STOP AND RESTART the node by
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

# Not under --summary: that reports on runs already archived and must not query the chain, so that
# it stays usable on a node whose chain is down -- which is one of the times you most want to read
# what the last runs did.
if [ $auto_skip -eq 1 ] && [ $summary_only -eq 0 ] && [ $clear_results -eq 0 ]; then
    echo "auto-skip: inspecting this node's place in the chain"
    auto=$(topology_skips)
    if [ -n "$auto" ]; then
        echo "auto-skip: skipping $auto  (override with --no-auto-skip)"
    else
        echo "auto-skip: nothing to skip -- this node can run the full suite"
    fi
fi

# ONE --skip, NOT TWO.
#
# Both lists used to be appended as separate --skip flags, and regression.sh parses that with
# `skip_list="$2"` -- so the SECOND one replaced the first and whichever list was appended last was
# the only one honoured. In practice that silently discarded the operator's own --skip, and the
# suites they asked to skip ran anyway. Worse, --dry-run merged the two correctly when reporting, so
# the preview said one thing and the run did another: the failure was invisible in the one output
# whose job is to predict the run. Caught running exactly that case on a local chain -- params ran
# despite being named in --skip.
effective_skip="$auto"
[ -n "$manual_skip" ] && effective_skip="${effective_skip:+$effective_skip,}$manual_skip"
[ -n "$effective_skip" ] && regression_args+=(--skip "$effective_skip")

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

# PER-SUITE TALLY ACROSS EVERY RUN OF THIS LOOP.
#
# history.tsv answers "did run 7 fail", which is the wrong question after a long soak.  What matters
# is WHICH SUITE keeps failing: one suite failing 9 times in 30 runs is a flaky test to chase, and
# nine suites failing once each is a chain that is sick.  Both look identical in a column of
# PASS/FAIL per run, and the per-run summaries scroll away.
#
# Suite rows are also appended to suites.tsv so the breakdown survives the loop being restarted --
# the in-memory tally only covers this invocation.
typeset -A agg_pass agg_fail agg_skip agg_secs
typeset -A agg_runfail        # run number -> how many suites failed in THAT run
typeset -a agg_order          # suites in FIRST-SEEN order == the order regression.sh runs them
agg_incomplete=0              # runs that produced no summary block at all
suite_file="$archive/suites.tsv"
[ -f "$suite_file" ] || printf 'run\tstarted\tsuite\tresult\tseconds\n' > "$suite_file"

tally_run() {   # results.json started
    local js="$1" when="$2" verdict label secs seen=0

    # NO FILE, OR A FILE THAT WILL NOT PARSE, MEANS THE RUN DID NOT FINISH.
    #
    # regression.sh writes this last and renames it into place, so its absence is not ambiguous: the
    # run was killed, or died before summarize().  Counted as incomplete rather than skipped
    # silently, because a run that scored nothing must not be able to hide inside a clean table.
    if [ ! -s "$js" ] || ! jq -e . "$js" >/dev/null 2>&1; then
        agg_incomplete=$(( agg_incomplete + 1 ))
        return 0
    fi

    # Read from a process substitution rather than a pipe: in zsh EVERY pipeline component runs in a
    # subshell, so `... | while read` would increment the arrays in a child and discard them.
    while IFS=$'\t' read -r verdict label secs; do
        seen=$(( seen + 1 ))
        [ -n "${agg_order[(r)$label]}" ] || agg_order+=("$label")
        [ "$verdict" = FAIL ] && agg_runfail[$run]=$(( ${agg_runfail[$run]:-0} + 1 ))
        case "$verdict" in
            PASS) agg_pass[$label]=$(( ${agg_pass[$label]:-0} + 1 ))
                  agg_secs[$label]=$(( ${agg_secs[$label]:-0} + secs )) ;;
            FAIL) agg_fail[$label]=$(( ${agg_fail[$label]:-0} + 1 )) ;;
            SKIP) agg_skip[$label]=$(( ${agg_skip[$label]:-0} + 1 )) ;;
        esac
        printf '%s\t%s\t%s\t%s\t%s\n' "$run" "$when" "$label" "$verdict" "$secs" >> "$suite_file"
    # @tsv, and IFS set to tab: a suite label containing a space would otherwise split across
    # $label and $secs and be tallied under a name that does not exist.  None do today, which is
    # exactly why it would go unnoticed the day one does.
    done < <(jq -r '.suites[] | [.result, .name, .seconds] | @tsv' "$js")

    # Parsed, but with an empty suite list -- a run that started and recorded nothing.
    [ "$seen" -gt 0 ] || agg_incomplete=$(( agg_incomplete + 1 ))
}

agg_last_printed=-1
print_aggregate() {
    [ "$run" -gt 0 ] || return 0
    # The loop prints after every run AND the EXIT trap prints again, which on a normal finish means
    # the same table twice in a row with nothing between them. Reprint only if a run has happened
    # since the last one -- so an abort part-way through a run still gets its summary.
    [ "$run" -ne "$agg_last_printed" ] || return 0
    agg_last_printed=$run
    local label p f s tot note avg
    # Runs that actually produced results.  Needed by the table below, not just the footer: a suite
    # skipped in every SCORED run is "never ran", and comparing against $run instead made that note
    # vanish as soon as one run died without results -- the note disappearing exactly when the data
    # got thinner.
    local scored=$(( run - agg_incomplete ))
    echo ""
    echo "======================================================================"
    echo "PER-SUITE TOTALS ACROSS $run RUN(S)"
    echo "======================================================================"
    printf "  %-22s %6s %6s %6s %7s   %s\n" "SUITE" "PASS" "FAIL" "SKIP" "AVG" "NOTE"
    # In run order, not alphabetical: the table then mirrors the lap, and the suites that dominate
    # the wall clock are read in the sequence they actually cost it.  agg_order holds every suite
    # ever seen, so one that has only ever failed still gets a row.
    for label in "${agg_order[@]}"; do
        p=${agg_pass[$label]:-0}; f=${agg_fail[$label]:-0}; s=${agg_skip[$label]:-0}
        tot=$(( p + f ))
        # Average over PASSES only.  A failing run aborts its suite early, so folding those in would
        # make a broken suite look FASTER -- the opposite of the truth.
        if [ "$p" -gt 0 ]; then avg="$(( (${agg_secs[$label]:-0} + p / 2) / p ))s"; else avg="-"; fi
        note=""
        # Flag the shapes worth acting on differently, rather than leaving the reader to divide.
        if [ "$f" -gt 0 ] && [ "$p" -gt 0 ]; then
            note="FLAKY ($f of $tot failed)"
        elif [ "$f" -gt 0 ]; then
            note="ALWAYS FAILS"
        elif [ "$s" -gt 0 ] && [ "$s" -eq "$scored" ]; then
            # Distinct from a blank note: this suite has no result at all, so a clean-looking table
            # is not evidence it works.  Usually auto-skip; --dry-run says which.
            note="never ran (skipped every run)"
        fi
        printf "  %-22s %6s %6s %6s %7s   %s\n" "$label" "$p" "$f" "$s" "$avg" "$note"
    done

    # WHETHER THE FAILURES CLUSTER -- the column above cannot answer this, and read alone it misleads.
    # A real archive of 115 runs showed eleven suites marked FLAKY; the failures were actually five
    # bad runs, two of which failed seven and eight suites AT ONCE.  That is one fault cascading, not
    # eleven flaky tests, and it points at the chain rather than at the suites.  Same numbers in the
    # table either way, opposite conclusions -- so the loop states which it saw instead of leaving
    # the reader to cross-reference suites.tsv by hand.
    local r nf tf=0 bad=0 cas=0 casf=0 caslist=""
    for r in ${(k)agg_runfail}; do
        nf=${agg_runfail[$r]}
        tf=$(( tf + nf )); bad=$(( bad + 1 ))
        if [ "$nf" -ge 3 ]; then cas=$(( cas + 1 )); casf=$(( casf + nf )); caslist="$caslist $r"; fi
    done
    echo ""
    if [ "$scored" -eq 0 ]; then
        echo "  NO RUN PRODUCED RESULTS -- nothing above is based on a completed run"
    elif [ "$bad" -eq 0 ]; then
        echo "  no failures in $scored scored run(s)"
    else
        echo "  $tf failure(s), in $bad of $scored scored run(s)"
        [ "$cas" -gt 0 ] && echo "  $casf of them landed in $cas run(s) that failed 3+ suites at once --" \
                                 "likely ONE fault, not many flaky suites: run${caslist}"
    fi
    # Loud, because these runs are invisible in every column above.
    [ "$agg_incomplete" -gt 0 ] && echo "  $agg_incomplete run(s) ended without a summary and are scored NOWHERE above"
    [ "$suite_file" = /dev/null ] || echo "  per-suite rows: $suite_file"
}

run=0

# --clear-results: START THE HISTORY OVER.
#
# The tally is only as useful as the runs it covers, and after a change to the chain or the suites
# the old runs describe a system that no longer exists -- a suite that failed nine times last week
# keeps reading as FLAKY long after the fix, which is the one thing this reporting must not do.
#
# It DELETES, so it says exactly what and asks first (-y to skip the prompt).  Only this loop's own
# archive is touched; the per-suite logs under logs/regression belong to regression.sh and are
# overwritten by its next run anyway.
if [ "$clear_results" -eq 1 ]; then
    setopt local_options null_glob
    # Counted from separate arrays rather than by filtering one combined list.  `${#${(M)a:#pat}}`
    # looks like "how many matched" and is not: the inner expansion joins to a scalar, so it returns
    # the LENGTH OF THAT STRING -- it reported 14056 of each here, a plausible-looking number in a
    # confirmation prompt for an unrecoverable delete.
    runfiles=("$archive"/run-*.json "$archive"/run-*.log)
    faildirs=("$archive"/failed-*)
    doomed=("${runfiles[@]}" "${faildirs[@]}")
    for f in "$history_file" "$suite_file"; do
        [ -e "$f" ] && doomed+=("$f")
    done
    if [ ${#doomed} -eq 0 ]; then
        echo "nothing to clear in $archive"
        exit 0
    fi
    echo "this will DELETE from $archive:"
    [ ${#runfiles} -gt 0 ] && printf '  %s run result file(s)\n' "${#runfiles}"
    [ ${#faildirs} -gt 0 ] && printf '  %s preserved failure dir(s)\n' "${#faildirs}"
    for f in "$history_file" "$suite_file"; do
        [ -e "$f" ] && printf '  %s\n' "$f"
    done
    if [ "$assume_yes" -ne 1 ]; then
        # Default NO on a bare Enter: this is unrecoverable and the archive is the only copy.
        printf 'proceed? [y/N] '
        read -r reply
        case "$reply" in
            [yY]|[yY][eE][sS]) ;;
            *) echo "left alone"; exit 0 ;;
        esac
    fi
    rm -rf -- "${doomed[@]}"
    echo "cleared ${#doomed} item(s); the next run starts the history over"
    exit 0
fi

# --summary: REPORT ON RUNS THAT ALREADY HAPPENED, then stop.
#
# The tally above only covers runs THIS invocation performed, which makes it useless in the case it
# is most wanted: a loop is already soaking, and restarting it to pick up the reporting would throw
# away the very history being asked about.  Every run archives its own log here, across every
# invocation, so the same two functions replay them and answer the question without disturbing
# anything -- in particular without writing over the file a running loop is still reading.
if [ "$summary_only" -eq 1 ]; then
    setopt local_options null_glob
    logs=("$archive"/run-*.json)
    if [ ${#logs} -eq 0 ]; then
        echo "no archived runs in $archive"
        exit 0
    fi
    # Oldest first, so run numbers in the clustering line read in chronological order.  Suite rows
    # are NOT appended to suites.tsv here: this replays history rather than making it, and writing
    # would duplicate every row a live loop already recorded.
    suite_file=/dev/null
    for f in ${(o)logs}; do
        run=$(( run + 1 ))
        tally_run "$f" "$(basename ${f%.json})"
    done
    print_aggregate
    exit 0
fi

# Print the tally however the loop ends -- max-runs, Ctrl-C, treasury floor or an error exit.  A
# summary that only appears on the happy path is missing exactly when it is most wanted.
trap print_aggregate EXIT

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
    runjson="$archive/run-$stamp.json"
    "$qadenatestscripts/regression.sh" "${regression_args[@]}" --json "$runjson" > "$runlog" 2>&1
    rc=$?
    ended=$(date -u +%FT%TZ)

    # The summary block is the useful part; the per-suite detail stays in logs/regression, which the
    # NEXT run overwrites -- so a failing run's suite logs are copied out before that can happen.
    sed -n '/^REGRESSION SUMMARY/,$p' "$runlog"
    # From the JSON, not from the printed line: the same reason the tally reads it.  Falls back to
    # the exit status alone if the run never wrote one, which is the case where there is no count.
    failed=$(jq -r '.counts.fail' "$runjson" 2>/dev/null)
    [[ "$failed" == <-> ]] || failed=0

    if [ "$rc" -ne 0 ]; then
        faildir="$archive/failed-$stamp"
        mkdir -p "$faildir"
        cp "$qadenabuild/logs/regression/"*.log "$faildir/" 2>/dev/null
        echo "run $run FAILED ($failed suite(s)); suite logs kept in $faildir"
        result=FAIL
    else
        result=PASS
    fi

    tally_run "$runjson" "$started"

    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$started" "$ended" "$run" "$result" "$failed" "$(treasury_qdn)" \
        >> "$history_file"

    # A running tally after every run, so a soak left overnight is readable at a glance in the
    # morning without reconstructing it from scrollback.
    print_aggregate

    [ "$pause" -gt 0 ] 2>/dev/null && sleep "$pause"
done

echo ""
echo "history: $history_file"
