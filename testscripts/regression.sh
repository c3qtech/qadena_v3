#!/bin/zsh
#
# Runs the whole regression suite and reports a summary.
#
# Covers every layer, from genesis construction to the credential flow:
#
#   genesis       buildscripts/init.sh, and the genesis it produces        (--from-genesis only)
#   chain         start the node and wait for blocks                       (--from-genesis only)
#   sgx-build     the SGX build is signed and REPRODUCIBLE                (--with-sgx)
#   prerequisites providers, oracles and the create-wallet sponsor, onboarded at runtime
#   idempotency   prerequisites re-run, asserting it issues ZERO transactions
#   setup         the test users, provisioned automatically when any is missing
#   pricefeed     oracle posting, per-market isolation, unregistered poster refused
#   pf-expiry     a posted price stops counting toward the median once it expires
#   transfers     transfer -> eph-wallet queue -> receive
#   suspicious    threshold scan, opt-in, and the regulator's report
#   bank-scan     direct bank sends are scanned too, and the whitelist takes individual add/remove
#   params        governance cannot set params that silently disable a control
#   uniqueness    identity uniqueness: duplicate issue vs duplicate claim, and update collisions
#   dsvs          document signing hash chain
#   wasm          store / instantiate / execute
#   evm           deploy / read / write / overwrite
#   cadena        cadena-smart-contracts: the GAA -> PAP -> SARO -> NCA -> Obligation -> DV chain
#   enf           enf-smart-contracts: the ENF notarial book (ENP registry + entries)
#   enclave-rollback  send a tx, roll chain+enclave back past it, prove the state reverted
#   enclave-crash     stall the enclave: the node must HALT, not fork, then recover
#   credentials   test_credentials.sh -- corrections, rejections, contacts, anti-squat,
#                 and key recovery (--skip recovery drops just the recovery cases)
#   replenish     al's ENCRYPTED balance is topped back up before anything spends it
#   peer-agreement   every peer computed the SAME app hash -- i.e. no fork
#   reclaim       the TRANSPARENT balance the suites accumulated goes back to the treasury
#
# Everything except the genesis/chain layers is IDEMPOTENT -- safe to repeat against the
# same chain.  They achieve that in different ways depending on what the module allows: delta
# assertions rather than absolute balances (transfers), per-run unique ids AND content (dsvs -- a
# document is keyed by content hash, so unique ids alone are not enough), fresh deploys (evm, wasm),
# top-up only when short (suspicious), end-state guards rather than "did I run before"
# (prerequisites).
#
# THAT CLAIM WAS TOO STRONG, and a repeat run proved it: only the FIRST run after genesis passed.
# test_suspicious.sh queued two transfers into ann-eph1 and drained one, so each run stranded an
# entry in that queue; the next run's test_transfers.sh drained the queue it was handed and measured
# a delta of -1,200,100 where it expected -100, and reported a transfer bug that did not exist.  The
# leftovers accumulated, one per run.  Fixed in test_suspicious.sh case 5, which now drains the
# queue it filled.  Repeating the suite is a property worth re-checking, because nothing here
# asserts it end to end -- the "idempotency" suite covers setup_prerequisites.sh and nothing else.
#
# Being repeatable is also not the same as being SUSTAINABLE: the suites drew about 6-9.4 million
# qdn per run from the treasury and gave none of it back, which is a day and a half of running before
# a 2 billion qdn genesis treasury is gone.  reclaim_funds() returns it -- both the transparent
# balance that piles up in ann and victor and, since receive-funds can unshield, the encrypted
# balance they accumulate as well.  replenish_funds() mints al's encrypted float from al's own
# transparent balance rather than borrowing it, so nothing has to be held back for it.
#
# WHAT IS NOT REPEATABLE IS OPT-IN.  Only two layers are left -- the credentials suite and its key
# recovery cases both came off this list once they provisioned per-run identities -- plus --with-sgx,
# which is opt-in for a different reason: it needs hardware, not a fresh chain.
#
#   --from-genesis   DESTRUCTIVE.  init.sh deletes $QADENAHOME outright -- chain data AND the
#                    keyring.  Everything is rebuilt from config/config.yml.
#                    It restores the tracked version files on exit, so it leaves no diff behind.
#   --with-sgx       REQUIRES REAL SGX HARDWARE (Ubuntu), ego and docker, and FAILS if they are
#                    absent rather than skipping.  Builds the enclave twice with --build-sgx and
#                    requires both builds to measure identically, which is the one property the
#                    whole attestation scheme rests on and which no other suite touches -- every
#                    other suite runs against a debug enclave whose identity is just a text file.
#                    Slow (two reproducible docker builds) and needs a CLEAN working tree, because
#                    --build-sgx runs `git clean -fd` before building.  Runs before every other
#                    functional suite.
#
# WHY THE ENCLAVE UPGRADE SUITE EXISTS.  check_upgrade_enclave.sh silently did nothing for a long
# time: its guard used a glob inside [[ ]], which zsh does not expand, so it exited 0 on every run
# and no upgrade was ever performed.  A new enclave would have come up with FRESH sealed keys and the
# chain would have looked perfectly healthy -- while every suspicious transaction report ever filed
# became permanently undecryptable, because the regulator private key exists nowhere else.
#
# Usage:
#   regression.sh                     the repeatable suite against a running chain
#   regression.sh --from-genesis      wipe, rebuild, and run everything
#   regression.sh --with-sgx          also verify the SGX build is signed and reproducible (SGX hw only)
#   regression.sh --stop-on-fail      stop at the first failure
#   regression.sh --skip a,b,c        do not run these suites
#   regression.sh --json PATH         also write the per-suite results as JSON (default: LOGDIR/results.json)
#
# THE JSON IS THE MACHINE-READABLE COPY of the summary table, written last.  Anything tallying
# results should read it rather than parse the printed table, whose layout is for humans and will
# change.  A run that dies part-way writes no JSON at all, which is how a caller tells "finished and
# passed" from "never finished" -- two things that look identical in a log that simply stops.
#
# SETUP HAS NO FLAG.  setup.sh runs automatically whenever the test users are incomplete -- checked
# against test_data/users.json in the keyring AND against the wallets this chain actually holds --
# and is skipped when they are all present.  --skip setup suppresses it.  There is deliberately no
# way to force a re-run; see the detection block further down for why forcing cannot repair anything.
#
# --skip exists for runs that must not lose the chain.  enclave-rollback and enclave-crash STOP AND
# RESTART the node by design, which is correct when the suite is the only thing using it and
# disastrous when it is not: a joining node sees the primary's RPC vanish for minutes, and snapshot
# accumulation restarts.  For a continuous run alongside a second node, use
#   --skip enclave-rollback,enclave-crash
# The auto-skip below decides this on evidence when nothing was passed.
#
# ONE --skip NAME IS NOT A SUITE:  `recovery` drops the key-recovery cases (6, 6a, 6b) from INSIDE
# the credentials suite while the rest of it still runs.  They run by default now -- they became
# repeatable when they moved to the per-run jill -- and the skip is an escape hatch for a chain that
# cannot spare the traffic, not a correctness gate.  It does not appear in the summary as its own
# line, because it is not its own suite; the run prints a note and the credentials log says SKIPPED.

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"


# NOTE: no `set -e` here.  This script's job is to run every test and report, so a failing test must
# not abort the runner.  Each test script has its own set -e.

function qadenad_alias { "$qadenabin/qadenad" --home "$QADENAHOME" "$@" }

from_genesis=false
with_sgx=false
stop_on_fail=false
skip_list=""
auto_skip=1
advertise_ip=""
json_out=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --from-genesis)     from_genesis=true; shift ;;
        --with-enclave-upgrade)
            print -u2 "regression.sh: --with-enclave-upgrade is gone.  The live-swap upgrade it drove was"
            print -u2 "               retired (ab839b3c); an enclave change is a governance plan now."
            print -u2 "               Use testscripts/test_fleet_upgrade.sh, or the fleet bringup's"
            print -u2 "               --test-fleet-upgrade, which upgrades every node at one height."
            exit 1 ;;
        --with-sgx)         with_sgx=true; shift ;;
        --stop-on-fail)     stop_on_fail=true; shift ;;
        --skip)             skip_list="$2"; shift 2 ;;
        --no-auto-skip)     auto_skip=0; shift ;;
        --json)             json_out="$2"; shift 2 ;;
        --advertise-ip-address) advertise_ip="$2"; shift 2 ;;
        --help)
            sed -n '/^# Usage:/,/^$/p' "$0" | sed 's/^# \{0,1\}//'

            # THE SKIPPABLE NAMES ARE READ OUT OF THIS FILE, not typed into the help text.  They are
            # exactly the labels run_test is called with, so a suite that is added, renamed or
            # removed shows up here correctly without anyone remembering to update a list -- and a
            # help text that names a suite --skip does not recognise is worse than none, because
            # --skip silently ignores a name it does not match and the suite runs anyway.
            echo "Skippable suites (--skip takes a comma-separated list of these):"
            grep -oE '^[[:space:]]*run_test "[a-z0-9-]+"' "$0" \
                | sed -E 's/.*run_test "([a-z0-9-]+)".*/\1/' | sort -u | tr '\n' ' ' \
                | fold -s -w 72 | sed 's/^/  /'
            echo ""
            echo "  genesis-init, genesis-check and chain-start exist only under --from-genesis,"
            echo "  sgx-build only under --with-sgx."
            echo ""
            echo "  Plus one name that is NOT a suite: recovery -- see above."
            exit 0
            ;;
        *) echo "Unknown option: $1"; echo "try: $0 --help"; exit 1 ;;
    esac
done

# PLACED AFTER THE ARGUMENT LOOP, and that is not cosmetic.  This block reads auto_skip, skip_list
# and from_genesis; sitting above their declarations it evaluated `[ $auto_skip -eq 1 ]` with an
# EMPTY variable, which zsh reports as
#     regression.sh:130: unknown condition: -eq
# on stderr and then carries on.  The guard silently never ran, skip_list stayed empty, and
# enclave-rollback executed on a fleet with peers -- the exact case it exists to prevent.
# Observed 2026-08-31.
# THE CHAIN-RESTARTING SUITES ARE UNSAFE ON SOME NODES, and this used to have no guard at all.
# enclave-rollback and enclave-crash stop and restart the node; on a fleet whose primary holds >= 1/3
# of the voting power that halts the whole chain, and a bare `regression.sh` did it without asking.
# The soak has refused this since it learned to, on the same evidence -- so the answer lives in
# setup_env.sh and both callers ask it.
#
# ANYTHING PASSED EXPLICITLY WINS: --skip is the operator saying what they want, and --no-auto-skip
# is "I know what enclave-crash does to this fleet".  The guard only fills a silence.
# PEERS FIRST, and this distinction is the whole correctness of the guard.  topology_skips answers
# "would stopping this node halt the chain", and on a SOLO node the answer is trivially yes -- it is
# 100% of the voting power.  But nothing else is watching: the suite stops it, the suite starts it,
# and the chain carries on.  Skipping there would delete real coverage, and it is coverage that
# demonstrably works -- a from-genesis primary runs enclave-rollback and enclave-crash green today,
# and that run is the last chance to exercise them before joiners arrive and make them unsafe.
#
# So the guard engages only once this node has PEERS, which is precisely when a self-stop stops
# being its own business.
if [ $auto_skip -eq 1 ] && [ -z "$skip_list" ]; then
    _peers=$(curl -s --max-time 5 localhost:26657/net_info 2>/dev/null | jq -r '.result.n_peers // 0' 2>/dev/null)
    [ -n "$_peers" ] || _peers=0
    if [ "$_peers" -gt 0 ]; then
        echo "auto-skip: $_peers peer(s) -- inspecting this node's place in the chain"
        skip_list=$(topology_skips)
        if [ -n "$skip_list" ]; then
            echo "auto-skip: skipping $skip_list  (override with --no-auto-skip)"
        else
            echo "auto-skip: nothing to skip -- every suite is safe on this node"
        fi
    else
        echo "auto-skip: no peers -- this node is alone, so a self-stop costs nothing.  Running everything."
    fi
    unset _peers
fi

logdir="$qadenabuild/logs/regression"
mkdir -p "$logdir"

names=()
results=()
seconds=()
failed=0

# Is <label> named in --skip?  Shared by run_test and by the case-group gates below (recovery), so
# both understand one spelling of --skip and cannot drift apart on how it is matched.
is_skipped() {
    [[ -n "$skip_list" ]] && print -r -- ",$skip_list," | grep -q ",$1,"
}

# run_test <label> <command> [args...]
run_test() {
    local label="$1"; shift

    # SKIPPED IS RECORDED, NOT SILENT.  A suite that vanishes from the summary is indistinguishable
    # from one that passed, and this runner's whole value is that its output means something.
    if is_skipped "$label"; then
        echo ""
        echo "======================================================================"
        echo ">>> $label"
        echo "======================================================================"
        echo "SKIP  (--skip)"
        names+=("$label")
        results+=("SKIP")
        seconds+=(0)
        return 0
    fi

    local logfile="$logdir/${label}.log"
    local start end rc

    echo ""
    echo "======================================================================"
    echo ">>> $label"
    echo "======================================================================"

    start=$(date +%s)
    "$@" > "$logfile" 2>&1
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

        # PRESERVE THE EVIDENCE.  $logfile is a FIXED NAME and the next run overwrites it, so in a
        # continuous loop a suite that fails once and passes next time leaves summary.log saying it
        # failed and nothing at all saying why -- the one log you want is the one just destroyed.
        # Failures are rare enough to keep whole, and an intermittent failure is exactly the kind
        # you cannot reproduce on demand.
        local keep="$logdir/failed/${label}-$(date -u +%Y%m%dT%H%M%SZ).log"
        mkdir -p "$logdir/failed"
        if cp "$logfile" "$keep" 2>/dev/null; then
            echo "      preserved -> $keep"
        fi
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

# Hand the build tree back to the user who invoked sudo.
#
# Under sudo every suite writes as root, so a run leaves root-owned files across the tree -- and,
# because an upgrade run makes a temporary commit, inside .git itself.  The next plain
# `git pull` then fails with
#
#     fatal: failed to write object / unpack-objects failed
#
# which reads like disk or corruption and is neither.  run_init already chowns before building, so
# --from-genesis recovered on its own; everything else -- a git pull, an editor, a non-sudo suite --
# was left broken until someone worked out why.
#
# Called from summarize(), which every exit path goes through.
restore_tree_ownership() {
    [ "$(id -u)" -eq 0 ] || return 0
    [ -n "$SUDO_USER" ] || return 0
    [ -d "$qadenabuild/.git" ] || return 0
    if chown -R "$SUDO_USER" "$qadenabuild" 2>/dev/null; then
        echo "build tree returned to $SUDO_USER"
    else
        echo "WARNING: could not return $qadenabuild to $SUDO_USER; 'git pull' may fail until you chown it"
    fi
}

summarize() {
    restore_tree_ownership

    # TEE'D TO A FILE THAT ACCUMULATES.  The per-suite logs are OVERWRITTEN by the next run -- same
    # filenames every time -- so a continuous loop leaves no history whatever: the only record of
    # run N is whatever scrolled past on a terminal nobody was watching.  summary.log keeps one
    # timestamped block per run, which is what you read to answer "has anything started failing?"
    mkdir -p "$logdir"
    {
    echo ""
    echo "======================================================================"
    echo "REGRESSION SUMMARY  $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "======================================================================"
    local i=1
    while [ $i -le ${#names[@]} ]; do
        printf "  %-6s %-28s %4ss\n" "${results[$i]}" "${names[$i]}" "${seconds[$i]}"
        i=$((i + 1))
    done
    echo "----------------------------------------------------------------------"
    # A run that never started is NOT a pass.  Every preflight refusal -- stop_qadena.sh failing, a
    # leftover process, an unreachable chain -- calls summarize before exiting, and with no suites
    # recorded the "all passed" branch printed
    #
    #     ALL 0 SUITES PASSED
    #
    # for a run that had done nothing at all.  Read by a human in a hurry, or by anything grepping
    # for PASSED, that is the most dangerous line the runner can emit.
    if [ ${#names[@]} -eq 0 ]; then
        echo "  NO SUITES RAN -- the run stopped before any test started (see above)"
    elif [ $failed -eq 0 ]; then
        # A SKIPPED SUITE IS NOT A PASSING ONE, and "ALL n SUITES PASSED" over a list containing
        # skips is the same false green this summary already guards against for an empty run.
        local skipped=0 r
        for r in "${results[@]}"; do
            [[ "$r" == "SKIP" ]] && skipped=$((skipped + 1))
        done
        if [ $skipped -gt 0 ]; then
            echo "  $(( ${#names[@]} - skipped )) SUITES PASSED, $skipped SKIPPED -- NOT A FULL RUN"
        else
            echo "  ALL ${#names[@]} SUITES PASSED"
        fi
    else
        echo "  $failed of ${#names[@]} SUITES FAILED"
    fi
    echo "======================================================================"
    echo "logs: $logdir"
    } | tee -a "$logdir/summary.log"

    emit_results_json
}

# THE SAME RESULTS, MACHINE-READABLE.
#
# run_regression_continually.sh used to recover these numbers by re-parsing the block printed above
# with sed and awk -- matching on leading whitespace, on the column the verdict happens to sit in,
# and on stripping the "s" off "33s". Every one of those is a property of how the table is FORMATTED,
# so widening a column or renaming a heading silently breaks the tallies, and breaks them QUIETLY:
# the parse yields nothing, the aggregate prints zero rows, and a clean-looking summary means the
# reader concludes nothing failed. The formatted table is for humans; this is for programs.
#
# A run killed part-way writes no file at all, which is precisely the signal wanted -- the loop can
# then distinguish "ran and passed" from "never finished", instead of both looking like silence.
# Written last, after the summary, so a partial file cannot be mistaken for a complete run.
emit_results_json() {
    local out="${json_out:-$logdir/results.json}" tmp i n pass=0 skip=0 esc
    mkdir -p "${out:h}" 2>/dev/null
    tmp="$out.tmp$$"

    for r in "${results[@]}"; do
        [[ "$r" == "PASS" ]] && pass=$((pass + 1))
        [[ "$r" == "SKIP" ]] && skip=$((skip + 1))
    done
    n=${#names[@]}

    {
        printf '{\n'
        printf '  "finished": "%s",\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        printf '  "host": "%s",\n' "${HOST:-$(hostname)}"
        printf '  "counts": { "total": %d, "pass": %d, "fail": %d, "skip": %d },\n' \
               "$n" "$pass" "$failed" "$skip"
        printf '  "suites": ['
        i=1
        while [ $i -le $n ]; do
            # Labels are plain identifiers today; escaped anyway so a future label with a quote in
            # it cannot produce a file that parses as valid JSON meaning something else.
            esc=${names[$i]//\\/\\\\}; esc=${esc//\"/\\\"}
            [ $i -gt 1 ] && printf ','
            printf '\n    { "name": "%s", "result": "%s", "seconds": %d }' \
                   "$esc" "${results[$i]}" "${seconds[$i]}"
            i=$((i + 1))
        done
        [ $n -gt 0 ] && printf '\n  '
        printf ']\n}\n'
    } > "$tmp"

    # Rename, so a reader never sees a half-written file. A truncated JSON would be a PARSE error
    # the loop reports as a broken run, which is a lie about the run rather than about the file.
    mv -f "$tmp" "$out"
}

# ---------------------------------------------------------------------------------------------
# suite bodies that are not standalone scripts
# ---------------------------------------------------------------------------------------------

# init.sh REFUSES to run as root; the SGX runtime scripts REQUIRE it.  Both are deliberate, and
# together they make a --from-genesis run on real SGX impossible in a single identity: as root,
# init.sh aborts ("init.sh must not be run as root"); as the user, run.sh aborts ("must be run as
# root (real SGX enclave)").  Nobody had hit this because nobody had run --from-genesis on SGX
# hardware with signed binaries before.
#
# So the runner drops privileges for exactly this one step.  That is safe because init.sh only builds
# and installs -- it starts no node and invokes nothing that wants root.
#
# THE NESTED sudo NEEDS ITS ENVIRONMENT CORRECTED, and getting this wrong is silent rather than
# loud: inside `sudo -u alvillarica`, SUDO_USER is set to *root*, so setup_env.sh would resolve
# QADENAHOME to /root/qadena and init.sh would build a perfectly good genesis into a directory
# nothing else ever looks at.  Unsetting SUDO_USER and supplying HOME sends setup_env.sh down its
# plain `cd ~` branch instead, and the result is asserted against what this process computed.
run_init() {
    if [ "$(id -u)" -ne 0 ] || [ -z "$SUDO_USER" ]; then
        "$qadenabuildscripts/init.sh" "$@"
        return $?
    fi

    local user_home
    user_home=$(getent passwd "$SUDO_USER" 2>/dev/null | cut -d: -f6)
    [ -n "$user_home" ] || { echo "could not resolve the home directory of $SUDO_USER"; return 1; }

    # If these disagree, everything after init.sh would look at a different chain than the one just
    # built -- the failure would surface much later as "chain is not reachable".
    if [ "$user_home/qadena" != "$QADENAHOME" ]; then
        echo "refusing to run init.sh as $SUDO_USER: it would use $user_home/qadena but this run expects $QADENAHOME"
        return 1
    fi

    # CLEAR $QADENAHOME WHILE STILL ROOT.  A previous run under sudo leaves root-owned chain data, and
    # init.sh -- now running as the user -- cannot delete it.  Its fallback is a nested `sudo rm`,
    # which stops to ask for a password again partway through a two-hour run.  Deleting it here is
    # not extra destruction: --from-genesis has already announced this directory is going, and
    # init.sh's own first act is to remove it.
    #
    # Guarded rather than trusted.  $QADENAHOME is assembled from a home directory and could in
    # principle come back as "/" or empty if getent misbehaved, and this runs as root.
    case "$QADENAHOME" in
        /*/qadena) rm -rf "$QADENAHOME" 2>/dev/null ;;
        *) echo "refusing to remove \$QADENAHOME=$QADENAHOME: not an absolute path ending in /qadena"; return 1 ;;
    esac

    # GIVE THE BUILD USER THE WHOLE BUILD TREE, rather than chasing individual directories.
    #
    # Everything after this point in the run executes as root and leaves root-owned files behind --
    # docker_*/output, provider_scripts/proposals, logs.  The NEXT run's init.sh executes as the
    # user and has to write into the same tree, so each of those becomes a failure, and they surface
    # far from their cause: the docker export one killed a build twenty minutes in with
    #
    #     error from receiver: failed to create .tmp.NNNNNNN: permission denied
    #
    # Handling them one at a time meant a new one appeared on each attempt.  One chown covers every
    # such file, including ones added later, and the target ownership is what a source checkout
    # should have had all along.  Restricted to $qadenabuild, which is a git working tree the user
    # already owns -- this restores that, it does not claim anything new.
    if [ -d "$qadenabuild/.git" ]; then
        chown -R "$SUDO_USER" "$qadenabuild" 2>/dev/null \
            || echo "warning: could not chown $qadenabuild to $SUDO_USER; a root-owned file may block the build"
    else
        echo "refusing to chown $qadenabuild: it is not a git working tree"
        return 1
    fi

    # The docker outputs are removed as well as chowned.  They are gitignored build artifacts that
    # every build regenerates, and a stale export directory has caused enough trouble already.
    local d
    for d in docker_build_chain docker_build_enclave docker_build_signer_enclave; do
        [ -d "$qadenabuild/$d/output" ] && rm -rf "$qadenabuild/$d/output"
    done

    # -i RUNS A LOGIN SHELL, which is what makes the toolchain visible.  sudo replaces PATH with
    # secure_path, so a plain `sudo -u` leaves ignite unable to find Go and it reports
    #
    #     Please, check that Go language is installed correctly in $PATH
    #
    # naming an installation that is present and working.  A login shell sources the user's profile
    # and restores their real PATH, and it sets HOME as a side effect.
    #
    # SUDO_USER must still be unset: inside the inner sudo it would be set to *root*, and
    # setup_env.sh keys QADENAHOME off it -- so init.sh would build into /root/qadena.
    echo "running init.sh as $SUDO_USER via a login shell (it refuses to run as root), home $user_home"
    sudo -u "$SUDO_USER" -i -- env -u SUDO_USER "$qadenabuildscripts/init.sh" "$@"
}

# init.sh only proves ignite accepted the file; these are the properties we actually care about
check_genesis() {
    local g="$QADENAHOME/config/genesis.json"
    [ -f "$g" ] || { echo "no genesis at $g"; return 1; }

    local orphans
    orphans=$(grep -oE "[A-Za-z0-9_-]+PubK(ID|_pubk)" "$g" | sort -u)
    if [ -n "$orphans" ]; then
        echo "unsubstituted placeholders left in genesis:"
        echo "$orphans"
        return 1
    fi
    echo "no unsubstituted placeholders"

    # THE ENCLAVE IDENTITY, which the check above does not cover -- it only matches *PubKID names.
    # config.yml ships genesis with the literal strings test-unique-id / test-signer-id, and
    # build_enclave.sh substitutes the ids it built.  If the build failed, those literals survive and
    # the chain can never accept its own enclave; the node simply fails to start, naming neither
    # genesis nor the build.  A run has already reached that state and reported genesis-check PASS.
    local g_unique g_signer
    g_unique=$(jq -r '.app_state.qadena.enclaveIdentityList[0].uniqueID // empty' "$g")
    g_signer=$(jq -r '.app_state.qadena.enclaveIdentityList[0].signerID // empty' "$g")
    if [ -z "$g_unique" ] || [ -z "$g_signer" ]; then
        echo "genesis has no enclave identity"
        return 1
    fi
    case "$g_unique" in
        test-unique-id|test-signer-id|"")
            echo "genesis still carries the placeholder enclave uniqueID '$g_unique' -- the enclave build did not substitute it, so the chain cannot accept its own enclave"
            return 1 ;;
    esac

    # On SGX the identity must additionally be a real 32-byte measurement.  A debug id like
    # "unique047" here would mean genesis was built by a debug build on a machine meant to run a
    # signed enclave -- which starts, then refuses the enclave for a mismatch that reads as a
    # runtime problem rather than a build one.
    if [ "$with_sgx" = "true" ]; then
        if [[ ! "$g_unique" =~ ^[0-9a-f]{64}$ ]] || [[ ! "$g_signer" =~ ^[0-9a-f]{64}$ ]]; then
            echo "--with-sgx but genesis names a non-measurement identity (uniqueID '$g_unique'); genesis was built by a DEBUG build"
            return 1
        fi
        local installed
        installed=$(ego uniqueid "$qadenabin/qadenad_enclave" 2>/dev/null)
        [ -n "$installed" ] \
            || { echo "no measurable enclave installed at $qadenabin/qadenad_enclave; the build did not produce one"; return 1; }
        [ "$installed" = "$g_unique" ] \
            || { echo "genesis names $g_unique but the installed enclave measures $installed"; return 1; }
        echo "genesis names the installed enclave measurement $g_unique"
    else
        echo "enclave identity substituted: $g_unique"
    fi

    python3 - "$g" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))['app_state']
ok = True

if 'crisis' in d:
    print("crisis module present; it was removed from the app"); ok = False
else:
    print("no crisis module")

nodes = sorted(x['nodeID'] for x in d['qadena']['intervalPublicKeyIDList'])
print("genesis nodes:", nodes)
if nodes != ['pioneer1', 'treasury']:
    print("expected exactly pioneer1 and treasury"); ok = False

srv = [x for x in d['qadena']['intervalPublicKeyIDList'] if x.get('nodeType') == 'srv-prv']
if srv:
    print("service providers in genesis:", [x['nodeID'] for x in srv]); ok = False
else:
    print("no service providers in genesis")

pf = d['pricefeed']
withor = [m['marketId'] for m in pf['params']['markets'] if m.get('oracles')]
if withor:
    print("markets with genesis oracles:", withor); ok = False
else:
    print(f"{len(pf['params']['markets'])} markets, none with a registered oracle")

withaddr = [p['marketId'] for p in pf['postedPriceList'] if 'oracleAddress' in p]
if withaddr:
    print("seeded prices carrying an oracleAddress:", withaddr); ok = False
else:
    print(f"{len(pf['postedPriceList'])} seeded prices, none attributed to an oracle")

sys.exit(0 if ok else 1)
PY
}

start_chain() {
    "$qadenascripts/start_qadena.sh" || return 1
    local i=0
    local started=false
    while [ $i -lt 60 ]; do
        if curl -s http://localhost:26657/status 2>/dev/null | grep -q latest_block_height; then
            local h
            h=$(curl -s http://localhost:26657/status | jq -r '.result.sync_info.latest_block_height')
            if [ "${h:-0}" -gt 0 ] 2>/dev/null; then
                echo "chain producing blocks, height $h"
                started=true
                break
            fi
        fi
        sleep 2
        i=$((i + 1))
    done
    if [ "$started" != "true" ]; then
        echo "chain did not produce a block within 120s"
        return 1
    fi

    # PRODUCING BLOCKS IS NOT THE SAME AS BEING READY.
    #
    # This used to return here, at height 1 or 2, and the suites that follow started transacting
    # immediately.  That worked only because the funding treasuries were exempt from AML scanning, so
    # the very first transactions never touched the enclave.  Now every account-to-account send is
    # scanned, and the enclave is not initialised yet: the node's BeginBlock triggers init at height
    # 2 and the enclave's registration tx must then land.  Returning early therefore handed the next
    # suite a chain that answers every query and refuses every send.
    #
    # The jar regulator is created by InitEnclave, so its presence on chain is the readiness signal --
    # and it is also precisely what a report needs, so once it exists the scan can measure AND report.
    local j=0
    while [ $j -lt 90 ]; do
        if [ "$(qadenad_alias query qadena list-jar-regulator --output json 2>/dev/null \
                | jq -r '.jarRegulator | length' 2>/dev/null)" -gt 0 ] 2>/dev/null; then
            echo "enclave initialised (jar regulator registered)"
            return 0
        fi
        sleep 2
        j=$((j + 1))
    done
    echo "the enclave did not initialise within 180s -- scanned bank sends would all be refused"
    return 1
}

# WHAT IS MISSING FROM THE SEEDED TEST USERS -- empty output means setup.sh has nothing to do.
#
# This replaced a single `keys show al` probe, which answered a much weaker question than the one
# the runner is actually asking.  al is the FIRST user setup.sh provisions, so his key exists after
# the very first thing it does; a setup killed halfway through -- or one whose parallel per-user
# jobs partly failed -- left al present and the runner declared the users fine, then handed the
# suites a chain missing dory (case 5), ann (case 13) or victor (the suspicious aggregates).  Those
# fail far from the cause, naming a credential or a balance rather than a user that was never made.
#
# Two things are checked, because either alone is misleading:
#
#   the keyring   every name in test_data/users.json.  This is what setup.sh iterates, so it is the
#                 definition of a complete set rather than a hand-copied list that can drift.
#   the chain     each of those keys must own a wallet HERE.  A keyring outlives the chain it was
#                 built against -- restore a snapshot, join a different network, or wipe chain data
#                 without wiping ~/.qadena, and every key still answers `keys show` while none of
#                 them exists on chain.
#
# THE CHAIN CHECK USES show-wallet PER USER.  It used to use one `list-wallet --limit 5000`, and
# that is what broke on 2026-08-23: the chain passed 5,000 wallets, jill's address sorts past the
# cut, and she was reported as owning no wallet at all.  The auto-setup below then fired and aborted
# on the ten users that DO exist, so every run stopped after three suites -- 64 of them, until
# someone read the logs.  A bigger --limit only moves the cliff; credential is already 28,428 and
# public-key 10,716 on the same node.  A bound large enough today is a bound that expires.
#
# NEVER TEST show-wallet's EXIT STATUS.  It EXITS 0 FOR A WALLET THAT DOES NOT EXIST: it is a
# balance view that reports the wallet lookup as one line among others, printing
#
#     err rpc error: code = NotFound desc = ... not found: key not found
#
# and then the transparent balance, successfully.  An `if ! show-wallet ...` check never fires -- it
# passes for every address, existing or not, which is the worst kind of check.  The OUTPUT is read
# instead, and read for two distinct markers rather than one: `walletID` means the wallet is here,
# `code = NotFound` means it genuinely is not.  pioneer1 is the case that proves the pair is needed
# -- it holds a transparent balance and no qadena wallet, so "did it print anything" says wallet
# while `walletID` correctly says none.
#
# A FAILED QUERY IS NOT AN EMPTY CHAIN.  An answer carrying NEITHER marker -- node down, timeout,
# half-written reply -- reports nothing missing rather than everything missing: "the chain did not
# answer" must not be turned into a reason to re-provision every user.  That is the same guard the
# old `jq -e has("wallet")` served, kept per-user now that the query is per-user.
#
# The ephemeral wallets are checked too, but only the four the suites hard-depend on: they are made
# by create_user.sh in the same pass as their owner, so they are a cheap way to notice a user whose
# provisioning died partway rather than a separate thing to verify.
setup_missing() {
    local usersjson="$qadenabuild/test_data/users.json"
    local names keyring name addr missing=""

    [ -f "$usersjson" ] || { echo "test_data/users.json"; return 0; }
    names=$(jq -r '.[].name' "$usersjson" 2>/dev/null)
    [ -n "$names" ] || { echo "test_data/users.json (unreadable)"; return 0; }

    # One keyring read for all of them; `keys show` per user would be a subprocess each.
    keyring=$(qadenad_alias keys list --keyring-backend test --output json 2>/dev/null \
        | jq -r '.[].name' 2>/dev/null)

    for name in ${(f)names} al-eph1 ann-eph1 ann-eph2 victor-eph1; do
        if ! print -r -- "$keyring" | grep -qx "$name"; then
            missing="$missing $name"
        fi
    done
    if [ -n "$missing" ]; then
        print -r -- "${missing# }"
        return 0
    fi

    # Keys all present -- now confirm they belong to THIS chain.
    #
    # ONE POINT QUERY PER USER, NOT ONE LIST OF EVERYTHING.  `list-wallet --limit 5000` truncated
    # silently: this chain passed 5,000 wallets on 2026-08-23, jill's address sorts past the cut,
    # and she was reported as having no wallet at all.  That tripped the auto-setup below, which
    # then aborted on the ten users that DO exist ("friendly name already exists"), and every run
    # stopped after three suites until someone read the logs.  64 consecutive runs died that way.
    #
    # Raising the limit only moves the cliff.  On that same node credential is already 28,428 and
    # public-key 10,716; any bound large enough today is a bound that expires.
    #
    # show-wallet EXITS 0 WHETHER OR NOT THE WALLET EXISTS -- it falls through to printing the
    # transparent bank balance -- so the exit status carries no information and must not be tested.
    # Its output is mixed prose and JSON (jq cannot parse it whole), so it is matched as text.
    local out
    for name in ${(f)names}; do
        addr=$(qadenad_alias keys show "$name" -a --keyring-backend test 2>/dev/null) || continue
        [ -n "$addr" ] || continue
        out=$(qadenad_alias query qadena show-wallet "$addr" --output json 2>&1)
        if print -r -- "$out" | grep -q "walletID"; then
            continue                                    # on this chain
        elif print -r -- "$out" | grep -q "code = NotFound"; then
            missing="$missing $name"                    # genuinely absent
        else
            # ABSENT AND UNREACHABLE ARE NOT THE SAME ANSWER.  Anything that is neither a wallet
            # nor an explicit NotFound -- node down, timeout, half-written reply -- means we do
            # not know.  Guessing "missing" here restarts setup against a populated chain, which
            # is the exact failure this function exists to prevent.
            echo "  (could not read $name's wallet; judged the test users on the keyring alone)" >&2
            return 0
        fi
    done
    [ -n "$missing" ] && print -r -- "${missing# } (keys exist, but no wallet on THIS chain)"
    return 0
}

# The prerequisites are idempotent by design; this proves it rather than assuming it.  A second run
# must issue no transactions and submit no proposals -- if a guard regresses, this catches it.
prerequisites_idempotent() {
    local out
    out=$("$qadenatestscripts/setup_prerequisites.sh" 2>&1) || { echo "$out"; return 1; }
    local txs proposals
    txs=$(echo "$out" | grep -cE '^txhash:|"txhash"')
    proposals=$(echo "$out" | grep -cE 'proposal id:')
    echo "$out" | grep -E "already|skipping" || true
    echo "transactions on the second run: $txs   proposals: $proposals"
    [ "$txs" -eq 0 ] && [ "$proposals" -eq 0 ]
}

# Encrypted (private) balance in whole qdn, as an integer string.  A wallet holds one entry per
# incoming transfer, so this sums them -- for an ephemeral wallet that is the depth of its queue.
# Mirrors enc_balance() in test_transfers.sh.
#
# "" means the wallet could not be read, which is NOT the same as a balance of zero: a wallet that
# answers and holds nothing gives 0.  The caller has to tell those apart, because topping up a
# wallet reported as empty when it simply could not be decrypted would move funds for no reason.
enc_qdn() {
    local addr raw out
    addr=$(qadenad_alias keys show "$1" -a --keyring-backend test 2>/dev/null) || { echo ""; return; }
    [ -n "$addr" ] || { echo ""; return; }
    raw=$(qadenad_alias query qadena show-wallet "$addr" --decrypt-as "$addr" 2>/dev/null) || { echo ""; return; }
    [ -n "$raw" ] || { echo ""; return; }
    out=$(echo "$raw" | perl -pe 's/\e\[[0-9;]*m//g' \
        | sed -n 's/^Encrypted balance \([0-9.]*\)qdn.*/\1/p')
    [ -n "$out" ] || { echo 0; return; }
    echo "$out" | python3 -c "
import sys
from decimal import Decimal
print(int(sum((Decimal(l.strip()) for l in sys.stdin if l.strip()), Decimal(0))))
"
}

# PUT AL'S ENCRYPTED BALANCE BACK BEFORE ANYTHING SPENDS IT.  This is a different pool from the one
# reclaim_funds() sweeps, and it leaks in a different way.
#
# reclaim_funds() moves TRANSPARENT balance, and that is not what test_transfers.sh spends.  Its
# transfers use the [from-encrypted-amount] slot of transfer-funds, so they draw on al's ENCRYPTED
# balance -- and while most of that suite is self-balancing (al collects back from the ephemeral
# wallets it funds), the 100qdn to ann-eph1 and the 25qdn to ann-eph2 are collected by ANN and are
# gone for good.  About 125qdn a run, and nothing anywhere puts it back: the treasury guards in
# test_suspicious.sh and test_evm.sh both fund the TRANSPARENT side.
#
# So al bled down to 50qdn and the next run died on its first transfer with
#
#     Pedersen generic error
#     FAILED: transfer-funds failed
#
# which names neither al nor a balance.  That is what this suite looks like, a few runs in, when it
# runs out of the one kind of money nothing refills.
#
# ann is where it all went, so ann is where it comes back from -- via al-eph1, because an encrypted
# balance can only be moved by transfer-funds into an ephemeral wallet and collected from there.
# al-eph1 is used by setup_protect_key.sh and sign_key_recovery.sh, neither of which is in this
# suite, and it is drained again immediately.
#
# RUNS BEFORE THE FUNCTIONAL SUITES, not after them with the reclaim.  A top-up at the end of a run
# is a top-up discovered one run too late: the run that first finds al short is the run that has
# already failed on it.
replenish_funds() {
    # test_transfers.sh permanently loses about 125qdn of al's encrypted balance per run (100 to
    # ann-eph1, 25 to ann-eph2, both collected by ann), and needs roughly 165qdn in hand to complete
    # one.  So:
    #
    #   minimum  what a single run cannot start without -- the only figure worth failing on
    #   floor    comfortable headroom (~300 runs), the point at which topping up is worth doing
    #   topup    how much to mint when it does
    #
    # AL FUNDS ITSELF, out of its own transparent balance.  An encrypted balance is not a separate
    # currency that has to be sourced from someone who already holds one: transfer-funds takes
    # [from-encrypted-amount] [from-transparent-amount], and the slot-2 form spends the sender's
    # TRANSPARENT balance to credit the recipient's ENCRYPTED one.  That is how ann got hers in the
    # first place -- test_suspicious.sh pushing al's transparent balance into ann-eph1 -- and pointing
    # it at al's own ephemeral wallet mints al's float directly.  Measured: al transparent -100,
    # al encrypted +100.
    #
    # An earlier version drew this from ann instead, on the theory that only a wallet already holding
    # an encrypted balance could supply one, and reserved 100,000qdn in ann to keep that possible.
    # That was wrong twice over: it coupled replenish to a donor wallet it does not need, and it
    # forced reclaim_funds() to leave behind the very balance it exists to recover.  al's transparent
    # balance is already kept up by the treasury guards in test_suspicious.sh and test_evm.sh, so
    # funding from there costs the chain nothing new.
    local al_enc_minimum=200
    local al_enc_floor=1000
    local al_enc_topup=50000
    local al_enc al_bank_qdn

    # CLEAR ANN'S EPHEMERAL QUEUES FIRST, whatever left something in them.
    #
    # test_transfers.sh measures a delta across receive-funds, which takes ONE queued entry per call,
    # so it is only correct against a queue holding just its own transfer.  test_suspicious.sh drains
    # what it queues (case 5) -- but only if it REACHES case 5.  When it aborted early instead, on
    # the report assertions that had gone blind at 100 records, its case-2 transfer had already
    # landed and the drain never ran.  Forty-odd such runs left twelve entries, 14,400,900qdn, sitting
    # in ann-eph1, and the next transfers run drained one of them and reported
    #
    #     FAILED: ann-eph1 released -1200000.000000000000000000, expected -100
    #
    # Cleaning up after yourself only works on the paths where you get to run.  Starting from a known
    # state works regardless of how the previous run died, which is the property a repeatable suite
    # actually needs.
    local eph drained total_drained=0
    for eph in ann-eph1 ann-eph2; do
        addr_of_eph=$(qadenad_alias keys show "$eph" -a --keyring-backend test 2>/dev/null) || continue
        [ -n "$addr_of_eph" ] || continue
        drained=0
        # Bounded: a queue this long is already an anomaly, and an unbounded loop here would spin on
        # a wallet that cannot be drained at all.
        while [ "$drained" -lt 40 ]; do
            [ "$(enc_qdn "$eph")" = "0" ] 2>/dev/null && break
            qadenad_alias tx qadena receive-funds "$eph" 0qdn --from ann --yes > /dev/null 2>&1 || break
            drained=$((drained + 1))
        done
        [ "$drained" -gt 0 ] && echo "drained $drained leftover queue entries from $eph"
        total_drained=$((total_drained + drained))
    done
    [ "$total_drained" -eq 0 ] && echo "ann's ephemeral queues were already empty"

    al_enc=$(enc_qdn al)
    [ -n "$al_enc" ] || { echo "could not read al's encrypted balance; leaving it alone"; return 0; }

    echo "al's encrypted balance: ${al_enc}qdn"
    if [ "$al_enc" -ge "$al_enc_floor" ] 2>/dev/null; then
        echo "at or above the ${al_enc_floor}qdn floor -- nothing to replenish"
        return 0
    fi

    # MINT IT FROM AL'S OWN TRANSPARENT BALANCE, capped by what al actually holds.
    al_bank_qdn=$(qadenad_alias query bank balances "$(qadenad_alias keys show al -a --keyring-backend test 2>/dev/null)" \
        --output json 2>/dev/null | jq -r '.balances[] | select(.denom=="aqdn") | .amount' 2>/dev/null)
    al_bank_qdn=$(python3 -c "print(int('${al_bank_qdn:-0}') // 10**18)" 2>/dev/null || echo 0)

    local want="$al_enc_topup"
    # Leave al enough transparent balance to pay gas and to be worth scanning; the treasury guards
    # top this side up during the run anyway.
    local usable=$((al_bank_qdn - 1000))
    [ "$usable" -lt 0 ] 2>/dev/null && usable=0
    [ "$usable" -lt "$want" ] 2>/dev/null && want="$usable"

    if [ "$want" -le 0 ] 2>/dev/null; then
        # al cannot fund itself.  Only a PROBLEM if it also cannot complete a run, which needs about
        # 165qdn (100 to ann-eph1, 25 to ann-eph2, 40 out and back through case 10).
        if [ "$al_enc" -ge "$al_enc_minimum" ] 2>/dev/null; then
            echo "al holds only ${al_bank_qdn}qdn transparent and cannot mint more, but its ${al_enc}qdn"
            echo "encrypted still covers the ${al_enc_minimum}qdn a run needs -- a note, not a failure"
            return 0
        fi
        echo "al holds ${al_bank_qdn}qdn transparent and ${al_enc}qdn encrypted, under the"
        echo "${al_enc_minimum}qdn a transfers run needs -- transfers will fail on its first send"
        return 1
    fi

    echo "minting ${want}qdn of encrypted balance for al from its own transparent balance, via al-eph1"
    # SLOT 2, not slot 1: [from-encrypted] [from-transparent].  0qdn from the encrypted side (which is
    # what is short) and the amount from the transparent side.
    qadenad_alias tx qadena transfer-funds al-eph1 0qdn "${want}qdn" \
        --transfer-note "regression replenish: al funding its own encrypted float" --from al --yes > /dev/null \
        || { echo "  al could not move its transparent balance into al-eph1"; return 1; }

    # The broadcast returns at the mempool, not at inclusion.
    local queued=false i=0
    while [ $i -lt 20 ]; do
        [ "$(enc_qdn al-eph1)" != "0" ] 2>/dev/null && { queued=true; break; }
        sleep 2
        i=$((i + 1))
    done
    [ "$queued" = "true" ] || { echo "  the transfer never reached al-eph1's queue"; return 1; }

    # 0qdn to the transparent side, so it lands as ENCRYPTED balance -- the whole point here.
    qadenad_alias tx qadena receive-funds al-eph1 0qdn --from al --yes > /dev/null \
        || { echo "  al could not collect from al-eph1"; return 1; }

    al_enc=$(enc_qdn al)
    echo "al's encrypted balance now: ${al_enc}qdn"
    # Judged against what a run NEEDS, not against the comfortable floor: a partial recycle that
    # leaves al able to run is a success, and demanding the floor here would fail a run that is
    # about to pass.
    [ -n "$al_enc" ] && [ "$al_enc" -ge "$al_enc_minimum" ] 2>/dev/null \
        || { echo "  al is still under the ${al_enc_minimum}qdn a transfers run needs"; return 1; }
}

# RETURN WHAT THE SUITES BORROWED, so the treasury survives being run against repeatedly.
#
# A run DRAWS far more from the treasury than it consumes, and this function is what closes the gap.
# What a run actually consumes is gas; the millions it draws move into the accounts the suites
# transact with and come back here.  Measured over three consecutive runs on the two-node testnet:
# 9,407,832qdn drawn on a run that funded everything, 7,007,732qdn on one that did not need the evm
# top-up.  Almost all of that is still on the chain when the run ends -- the question was only
# whether anything went and got it.
#
# Two of the three big draws are already guarded ("top up al if short"), so they stop firing the
# moment al is solvent again.  Reclaiming is therefore enough on its own: put the balance back and
# the guards go quiet.
#
# WHY IT UNSHIELDS BEFORE IT SWEEPS.  transfer-funds takes [from-encrypted-amount]
# [from-transparent-amount], and the large transfers in test_suspicious.sh spend the TRANSPARENT side
# to credit the recipient's ENCRYPTED balance.  A sweep that moved transparent balance ONLY would
# leave everything that crossed over sitting with ann, and the transparent pool would still shrink by
# roughly 2.4 million qdn a run -- which is exactly what this function did until it learned to
# unshield, and why the numbers above were once read as a per-run drain.
#
# So it UNSHIELDS FIRST, then sweeps.  receive-funds takes [to-transparent-amount], so collecting a
# transfer with an amount rather than the 0qdn every other caller passes brings the funds back out as
# transparent balance -- measured exactly, and asserted by case 10 of test_transfers.sh.  An earlier
# version of this comment claimed the opposite, that nothing unshields an encrypted balance and only
# --from-genesis could reset the pool; that was wrong, read off transfer-funds' signature and the Msg
# service without checking what receive-funds' second argument does, and it is why this function
# spent so long walking past most of the money.
#
# WHAT IT USED TO WALK PAST, measured on the rebuilt chain after two runs: ann held 4,750,750qdn and
# victor 3,860,500qdn encrypted, 8.6 million between them, against a transparent sweep that recovered
# 3.2 million.  victor is the sharper case -- the sweep looked at its 500qdn transparent balance,
# found it under the float, and logged "nothing to reclaim" while it sat on 3.8 million.
#
# NOTHING NEEDS TO BE HELD BACK.  An earlier version reserved 100,000qdn in ann, believing
# replenish_funds() could only source al's encrypted float from a wallet that already had one.  It
# cannot only do that: al mints its own from its own transparent balance (see replenish_funds), so
# both accumulators are swept to a token float here.
#
# Best-effort by design: a reclaim that cannot run leaves the chain exactly as the suites left it,
# which is the old behaviour and no worse.  It reports what it moved and fails only if a send it
# actually attempted was refused, because that would mean the scan started rejecting a wallet-to-
# wallet send that test_bank_restriction.sh asserts is allowed.
reclaim_funds() {
    # Enough for gas on the next run's transactions, and small enough that leaving it is free.
    local float_qdn=1000
    local treasury_addr acct addr have surplus result hash
    local reclaimed=0 failures=0

    treasury_addr=$(qadenad_alias keys show treasury -a --keyring-backend test 2>/dev/null)
    [ -n "$treasury_addr" ] || { echo "treasury not in the keyring; nothing to reclaim into"; return 0; }

    # UNSHIELD BEFORE SWEEPING, so what comes out of an encrypted balance is carried to the treasury
    # by the transparent sweep below in the SAME pass rather than sitting a run behind.
    #
    # ann-eph2 and victor-eph1 are the routes: an encrypted balance can only move through an
    # ephemeral wallet.  ann-eph1 is left alone because test_transfers.sh measures deltas against it;
    # replenish_funds() clears both of ann's queues at the start of every run anyway, and nothing
    # asserts on victor-eph1's balance.
    #
    # The explicit amount is used rather than `all`.  Both work on a current binary, but `all` needed
    # a fix to set the token denom (x/qadena/client/cli/tx_receive_funds.go) and an older qadenad
    # would fail on it with "There are no funds enqueued for"; the amount form works on any binary.
    local reserve eph enc_have enc_surplus before_t after_t
    local unshielded=0
    for pair in "ann ann-eph2 1000" "victor victor-eph1 1000"; do
        acct=${pair%% *}; eph=$(echo "$pair" | awk '{print $2}'); reserve=$(echo "$pair" | awk '{print $3}')

        addr=$(qadenad_alias keys show "$acct" -a --keyring-backend test 2>/dev/null) || continue
        [ -n "$addr" ] || continue
        qadenad_alias keys show "$eph" -a --keyring-backend test > /dev/null 2>&1 || continue

        # DRAIN THE TARGET QUEUE FIRST, before putting anything into it.
        #
        # An ephemeral wallet's queue is FIFO -- test_transfers.sh case 9 asserts exactly that -- and
        # receive-funds takes the entry at the HEAD, not the one you just sent.  Transferring into a
        # queue that already holds entries therefore collects somebody else's, and asking to unshield
        # more than that entry holds simply fails:
        #
        #     victor-eph1:  350000, 350000, 10000, 5619500   <- the last one is ours
        #     victor could not collect 5619500qdn out of victor-eph1 as transparent
        #
        # test_suspicious.sh drains victor-eph1 best-effort in a loop of six and can leave more than
        # that behind, so this is the normal state of that wallet rather than a rare one.  Draining
        # first makes the collect below unambiguous AND recovers the leftovers, which are real funds.
        local pre_drained=0
        while [ "$pre_drained" -lt 40 ]; do
            [ "$(enc_qdn "$eph")" = "0" ] 2>/dev/null && break
            qadenad_alias tx qadena receive-funds "$eph" 0qdn --from "$acct" --yes > /dev/null 2>&1 || break
            pre_drained=$((pre_drained + 1))
        done
        [ "$pre_drained" -gt 0 ] && echo "$acct: recovered $pre_drained stranded queue entries from $eph first"

        enc_have=$(enc_qdn "$acct")
        [ -n "$enc_have" ] || { echo "$acct: could not read the encrypted balance; skipping the unshield"; continue; }
        enc_surplus=$((enc_have - reserve))
        if [ "$enc_surplus" -le 0 ] 2>/dev/null; then
            echo "$acct holds ${enc_have}qdn encrypted, at or under its ${reserve}qdn reserve -- nothing to unshield"
            continue
        fi

        echo "unshielding ${enc_surplus}qdn from $acct via $eph (reserve ${reserve}qdn)"
        before_t=$(qadenad_alias query bank balances "$addr" --output json 2>/dev/null \
            | jq -r '.balances[] | select(.denom=="aqdn") | .amount' 2>/dev/null)

        # --opt-in-reason because this is far over the reporting threshold.  Without one the transfer
        # is still allowed and reported by default, but a chain with
        # block_transfer_without_opt_in_reason set to true would refuse it -- and a reclaim that
        # silently stops working on such a chain is exactly the failure this suite exists to catch.
        if ! qadenad_alias tx qadena transfer-funds "$eph" "${enc_surplus}qdn" 0qdn \
            --opt-in-reason "regression reclaim: returning the suite's encrypted balance" \
            --transfer-note "regression reclaim: unshield" --from "$acct" --yes > /dev/null 2>&1; then
            echo "  $acct could not move its encrypted balance into $eph"
            failures=$((failures + 1)); continue
        fi

        # The broadcast returns at the mempool, not at inclusion, so wait for the queue to show it.
        local queued=false i=0
        while [ $i -lt 20 ]; do
            [ "$(enc_qdn "$eph")" != "0" ] 2>/dev/null && { queued=true; break; }
            sleep 2
            i=$((i + 1))
        done
        [ "$queued" = "true" ] || { echo "  the transfer never reached $eph's queue"; failures=$((failures + 1)); continue; }

        if ! qadenad_alias tx qadena receive-funds "$eph" "${enc_surplus}qdn" --from "$acct" --yes > /dev/null 2>&1; then
            echo "  $acct could not collect ${enc_surplus}qdn out of $eph as transparent"
            failures=$((failures + 1)); continue
        fi
        sleep 4

        after_t=$(qadenad_alias query bank balances "$addr" --output json 2>/dev/null \
            | jq -r '.balances[] | select(.denom=="aqdn") | .amount' 2>/dev/null)
        # `local x` with no assignment PRINTS x=value in zsh when x is already set (local is
        # typeset, and a bare typeset lists the parameter).  Inside this loop that leaked a stray
        # "gained=2400124" into the reclaim log on the second iteration.  Assigning at declaration
        # keeps it quiet.
        local gained=0
        gained=$(python3 -c "print((int('${after_t:-0}') - int('${before_t:-0}')) // 10**18)" 2>/dev/null || echo 0)
        echo "  $acct transparent +${gained}qdn (now unshielded, swept below)"
        unshielded=$((unshielded + gained))

        # Drain anything the collect left behind, so the next run starts from an empty queue.
        for _ in {1..6}; do
            [ "$(enc_qdn "$eph")" = "0" ] 2>/dev/null && break
            qadenad_alias tx qadena receive-funds "$eph" 0qdn --from "$acct" --yes > /dev/null 2>&1 || break
        done
    done
    [ "$unshielded" -gt 0 ] && echo "unshielded ${unshielded}qdn in total"

    # Now the transparent sweep, which also carries whatever the unshield above just produced.
    #
    # ann accumulates as the counterparty for the 2,000,000qdn over-threshold send in
    # test_bank_restriction.sh and for the evm suite's bank leg; victor as the destination for
    # test_suspicious.sh's aggregate cases.  al is a net SPENDER and is deliberately left alone --
    # refilling it is what the treasury guards are for, and taking from it here would just make them
    # fire again.  The per-run throwaway keys (bankscan-*, evmsrc-*, evmdst-*) hold about 570qdn
    # between them and are not worth enumerating.
    for acct in ann victor; do
        addr=$(qadenad_alias keys show "$acct" -a --keyring-backend test 2>/dev/null) || continue
        [ -n "$addr" ] || continue

        have=$(qadenad_alias query bank balances "$addr" --output json 2>/dev/null \
            | jq -r '.balances[] | select(.denom=="aqdn") | .amount' 2>/dev/null)
        [ -n "$have" ] || continue
        have=$(python3 -c "print(int('$have') // 10**18)")

        if [ "$have" -le "$float_qdn" ] 2>/dev/null; then
            echo "$acct holds ${have}qdn, at or under the ${float_qdn}qdn float -- nothing to reclaim"
            continue
        fi

        surplus=$((have - float_qdn))
        echo "reclaiming ${surplus}qdn from $acct"

        # Scanned like any other wallet-to-wallet send, and over the reporting threshold, so it files
        # a report and is allowed -- exactly what test_bank_restriction.sh asserts for a send this
        # size.  The extra report is harmless: every suite that counts reports re-reads its own
        # baseline at the point it needs one.
        #
        # STDERR IS NOT CAPTURED, deliberately.  --gas auto writes "gas estimate: NNNN" to stderr,
        # and folding that into the capture with 2>&1 leaves jq parsing "gas estimate: 84302{...}"
        # -- which yields no txhash, so a send that had ALREADY LANDED was reported as a failure.
        # Every other suite captures this command the same way, without 2>&1.
        result=$(qadenad_alias tx bank send "$acct" "$treasury_addr" "${surplus}qdn" \
            --from "$acct" --yes --output json \
            --gas-prices $minimum_gas_prices --gas $gas_auto --gas-adjustment $gas_adjustment) \
            || { echo "  send from $acct was refused"; failures=$((failures + 1)); continue; }

        # CHECK THE BROADCAST CODE, not just the exit status.  A CheckTx rejection exits 0 and still
        # returns JSON -- with a non-zero .code and the reason in .raw_log -- so a send refused at
        # broadcast would otherwise reach the wait below and be reported as "did not land", which
        # names the symptom and discards the explanation the node already gave.
        local code=""
        code=$(echo "$result" | jq -r '.code // 0' 2>/dev/null)
        if [ "$code" != "0" ] && [ -n "$code" ]; then
            echo "  broadcast from $acct rejected with code $code: $(echo "$result" | jq -r '.raw_log // ""' 2>/dev/null | head -c 200)"
            failures=$((failures + 1)); continue
        fi

        hash=$(echo "$result" | jq -r '.txhash' 2>/dev/null)
        [ -n "$hash" ] && [ "$hash" != "null" ] \
            || { echo "  no txhash from the send"; failures=$((failures + 1)); continue; }

        # 90s, then a RE-QUERY, because "wait-tx gave up" is not "the transaction did not land".  At
        # 30s on a loaded two-core box this reported a failure for a send that was merely slow.  The
        # re-query distinguishes the two: if the transaction is genuinely absent it was dropped from
        # the mempool rather than executed, and the balance below will show it.
        if ! qadenad_alias query wait-tx "$hash" --timeout 90s > /dev/null 2>&1; then
            if ! qadenad_alias query tx "$hash" > /dev/null 2>&1; then
                echo "  reclaim tx $hash never made it into a block (dropped, not executed)"
                failures=$((failures + 1)); continue
            fi
            echo "  reclaim tx $hash landed late, after wait-tx gave up"
        fi

        reclaimed=$((reclaimed + surplus))
    done

    echo "reclaimed ${reclaimed}qdn to the treasury"
    [ "$failures" -eq 0 ]
}

# ---------------------------------------------------------------------------------------------

echo "======================================================================"
echo "QADENA REGRESSION SUITE"
echo "======================================================================"

if [ "$from_genesis" = "true" ]; then
    echo ""
    echo "!! --from-genesis: this DELETES $QADENAHOME -- chain data and keyring !!"
    if [ -z "$advertise_ip" ]; then
        advertise_ip=$("$qadenabuildscripts/get_default_ip.sh" 2>/dev/null)
        [ -n "$advertise_ip" ] || { echo "could not determine an IP; pass --advertise-ip-address"; exit 1; }
    fi
    echo "advertising $advertise_ip"

    # the node has to be down before its home directory is removed out from under it
    #
    # THE RESULT IS CHECKED.  This used to discard both output and exit status, which hid a
    # stop_qadena.sh that could not kill a (since-deleted) run_enclave.sh respawn loop: the loop
    # kept restarting a DEBUG enclave, is_qadena_running stayed true, and start_qadena.sh then
    # reported "already running" and never launched the chain.  The run failed 25 minutes later with
    # "chain did not produce a block within 120s", naming nothing that had gone wrong.
    if ! "$qadenascripts/stop_qadena.sh"; then
        echo "stop_qadena.sh reported failure; refusing to rebuild on top of a node that is still running"
        summarize
        exit 1
    fi
    sleep 2

    # Independently confirmed, because "stop succeeded" and "nothing is running" are not the same
    # claim -- a supervisor can respawn a process after the script has finished checking.
    #
    # `ps -eo pid,args`, NOT `pgrep -af`.  BSD pgrep (macOS) has no -a, so it printed bare PIDs with
    # no command line -- and the `grep -v regression.sh` below then had nothing to match on and could
    # not exclude anything, including this script's own process.  The check duly tripped on itself:
    #
    #     processes are still alive after stop_qadena.sh:
    #     40504
    #     a --from-genesis run cannot proceed with a live node or a respawn loop
    #
    # with no command shown, because there was none to show.  ps -eo pid,args prints the full command
    # on both platforms, so the self-filter works and a real leftover is named rather than numbered.
    leftover=$(ps -eo pid,args 2>/dev/null \
        | grep -E "qadenad|cosmovisor run|run_enclave\.sh|run_signerenclave\.sh|ego-host" \
        | grep -v "grep" | grep -v "regression\.sh" || true)
    if [ -n "$leftover" ]; then
        echo "processes are still alive after stop_qadena.sh:"
        echo "$leftover"
        echo "a --from-genesis run cannot proceed with a live node or a respawn loop"
        summarize
        exit 1
    fi

    # --with-sgx MUST propagate to init.sh.  genesis.json is written with the enclave ids produced by
    # the build, so a debug-built genesis names debug ids -- and the SGX enclave installed later
    # would be refused by the very chain this run just created, for an identity mismatch that looks
    # nothing like a build problem.  One flag, so the two cannot drift apart.
    if [ "$with_sgx" = "true" ]; then
        run_test "genesis-init" run_init --advertise-ip-address "$advertise_ip" --build-sgx
    else
        run_test "genesis-init" run_init --advertise-ip-address "$advertise_ip"
    fi

    # STOP HERE IF IT FAILED, regardless of --stop-on-fail.  init.sh deletes $QADENAHOME as its first
    # act, so a failure BEFORE that point leaves the previous chain fully intact -- and everything
    # downstream then runs against it and passes.  That is worse than a failure: genesis-check
    # validates the OLD genesis and reports PASS, and the summary ends up showing one red line above
    # a wall of green that describes a chain this run never built.
    if [ "${results[-1]}" = "FAIL" ]; then
        echo ""
        echo "genesis-init FAILED and \$QADENAHOME still holds the PREVIOUS chain."
        echo "Everything after this would test that older chain and pass, so the run stops here."
        summarize
        exit 1
    fi

    run_test "genesis-check" check_genesis
    run_test "chain-start" start_chain
fi

# Every remaining suite assumes a running chain.  Failing once here beats the same error repeated
# eight times with eight different messages.
if ! qadenad_alias status > /dev/null 2>&1; then
    echo ""
    echo "FAILED: chain is not reachable."
    echo "  start it with:  scripts/start_qadena.sh"
    echo "  or rebuild:     $0 --from-genesis"
    summarize
    exit 1
fi
echo ""
echo "chain up at height $(qadenad_alias status 2>/dev/null | jq -r '.sync_info.latest_block_height' 2>/dev/null || echo '?')"

run_test "prerequisites" "$qadenatestscripts/setup_prerequisites.sh"
run_test "idempotency"   prerequisites_idempotent

# SETUP RUNS WHEN IT IS NEEDED, rather than when someone remembered the flag.
#
# The runner already knew how to tell -- it just refused to act on the answer: it checked for al,
# printed "run: regression.sh --with-setup" and exited 1.  That was a fully-diagnosed problem with a
# known fix, handed back to the operator to retype.  Worse, it is the shape of failure that wastes
# the most time in a continuous loop or an unattended bring-up, where nobody is watching to retype
# anything and the run simply stops.
#
# THERE IS NO --with-setup, and there deliberately is no way to force a re-run.  Forcing was never
# a repair: setup.sh provisions through create_user.sh, which issues `tx qadena create-wallet`
# UNCONDITIONALLY under `set -e`, and the chain refuses a second wallet for an address it already
# knows (ErrWalletExists, x/qadena/types/errors.go:28; msg_server_create_wallet.go:26).  So a forced
# run against a populated chain aborts on its first user instead of fixing anything -- a flag whose
# only outcomes are "unnecessary" and "broken".  What replaced it is the detection below, which is
# the question the flag was standing in for anyway.
#
# --skip setup means never, and is honoured even when users are missing -- the run then proceeds and
# fails in whichever suite needs them, which is what an explicit skip asks for.
if is_skipped "setup"; then
    setup_missing_names=$(setup_missing)
    if [ -n "$setup_missing_names" ]; then
        echo ""
        echo "WARNING: --skip setup, but the test users are incomplete:"
        echo "  $setup_missing_names"
        echo "  suites that need them will fail; drop --skip setup to provision them"
    fi
    run_test "setup" "$qadenatestscripts/setup.sh"   # records the SKIP in the summary
else
    setup_missing_names=$(setup_missing)
    if [ -n "$setup_missing_names" ]; then
        echo ""
        echo "the test users are incomplete -- missing:"
        echo "  $setup_missing_names"
        echo "running setup.sh automatically (--skip setup to suppress this)"
        run_test "setup" "$qadenatestscripts/setup.sh"

        # A FAILED SETUP MUST STOP THE RUN, regardless of --stop-on-fail.  Every suite below reads
        # these users, so continuing produces a wall of failures that all describe the same cause
        # once and the summary loses which one was real.
        if [ "${results[-1]}" = "FAIL" ]; then
            echo ""
            echo "setup.sh FAILED and every suite below depends on the users it provisions."
            echo "The run stops here rather than reporting the same cause a dozen times."
            summarize
            exit 1
        fi
    else
        echo "test users complete and on this chain -- setup.sh has nothing to do"
    fi
fi

# BEFORE the suites that spend, so al is solvent in both pools when they start.
run_test "replenish"   replenish_funds

run_test "pricefeed"   "$qadenatestscripts/test_pricefeed.sh"
run_test "pf-expiry"   "$qadenatestscripts/test_pricefeed_expiry.sh"
run_test "transfers"   "$qadenatestscripts/test_transfers.sh"
if [ "$with_sgx" = "true" ]; then
    # FIRST among the functional suites, for two reasons.  A broken or non-reproducible SGX build
    # should fail before an hour of chain tests runs on top of it; and it must come before anything
    # that leaves the installed enclave at a measurement NEWER than the committed source (the fleet
    # upgrade does exactly that) -- a --build-sgx after that would install the older measurement as
    # main and the node would then find no sealed params matching it.
    run_test "sgx-build"   "$qadenatestscripts/test_sgx_build.sh"
fi

run_test "suspicious"  "$qadenatestscripts/test_suspicious.sh"
run_test "bank-scan"   "$qadenatestscripts/test_bank_restriction.sh"
run_test "params"      "$qadenatestscripts/test_params_validation.sh"
run_test "uniqueness"  "$qadenatestscripts/test_credential_uniqueness.sh"

# CREDENTIALS RUNS BY DEFAULT NOW.  It used to be opt-in because it corrected the SHARED seeded
# identities -- which burned single-use claim codes and put al/jill/dory inside a 10000-block
# update cool-down, so it could not repeat and had to run LAST to avoid disturbing suites that read
# those users.  It now provisions its own four identities per run via setup.sh --prefix, so neither
# constraint applies and it can sit here with the other credential suites.  Skippable like any
# other: --skip credentials.
#
# ITS KEY RECOVERY CASES (6, 6a, 6b) RUN TOO, and used to need a --with-credentials opt-in.  They
# were once-per-chain only because they ran against the SHARED jill: one protect-key, one set of
# claim codes, both consumed on the first run.  Now they file a per-run protect-key against the
# per-run jill this suite provisions, with per-run recovery wallets, mnemonics and claim codes, so
# nothing carries between runs and they repeat like everything else -- which finally puts the
# hash-aliasing case, the only test anywhere of recovery via a PRE-MARRIAGE surname, into the
# continuous loop instead of only into --from-genesis runs.
#
# Skippable ON ITS OWN, without losing the rest of the suite: --skip recovery.  That is one --skip
# vocabulary for both, and run_regression_continually.sh already forwards --skip verbatim.
if is_skipped "recovery"; then
    export TEST_CREDENTIALS_SKIP_RECOVERY=1
    # Only worth saying when credentials is actually going to run -- "credentials will run without
    # its recovery cases" is a confusing thing to print immediately above `credentials  SKIP`.
    if ! is_skipped "credentials"; then
        echo ""
        echo "note: --skip recovery -- credentials will run WITHOUT its key-recovery cases (6, 6a, 6b)"
    fi
else
    unset TEST_CREDENTIALS_SKIP_RECOVERY
fi
run_test "credentials" "$qadenatestscripts/test_credentials.sh"
# Immediately after uniqueness because that is the suite the rotation race kept breaking: a VShare
# bound just before the SS interval key rotated was rejected as invalid (qadena code 1142).  This
# forces rotations rather than waiting 555 blocks for one.  Skips loudly on real SGX, where the
# enclave refuses a forced rotation.
run_test "ss-rotation" "$qadenatestscripts/test_ss_key_rotation.sh"
run_test "dsvs"        "$qadenatestscripts/test_dsvs.sh"
run_test "wasm"        "$qadenatestscripts/test_wasm.sh"
run_test "evm"         "$qadenatestscripts/test_evm.sh"
run_test "cadena"      "$qadenatestscripts/test_cadena_contracts.sh"
run_test "enf"         "$qadenatestscripts/test_enf_contracts.sh"

# Chain+enclave rollback, and the crash that made it necessary.  Placed here, after every suite
# that writes, for two reasons: the rollback suite wants real transactions behind it so the
# state it erases is non-trivial, and both suites RESTART THE NODE -- run earlier, every later
# suite would inherit a restarted chain and any flake in them would be blamed on the wrong thing.
#
# They restart the node but leave it running, so peer-agreement below still has a live chain to
# compare.  Neither skips when the chain is down: a rollback bug is a fork bug, and a suite that
# skips silently reports success while testing nothing.
run_test "enclave-rollback"  "$qadenatestscripts/test_enclave_rollback.sh"
run_test "enclave-crash"     "$qadenatestscripts/test_enclave_crash_recovery.sh"

# LAST of the always-on suites, and deliberately after everything that writes: a fork shows up in
# the app hash only once the suites have put transactions through.  Run early it would compare two
# idle nodes and pass regardless.  It is also the only thing that would notice if the rollback
# suites above left this node disagreeing with a peer.
run_test "peer-agreement" "$qadenatestscripts/test_peer_agreement.sh"

# AFTER every suite that spends.  The enclave upgrade that used to run after this is gone: it was a
# live swap, and an enclave change is a governance plan at a height now.  Upgrading is therefore a
# FLEET operation and cannot run from inside a single-node suite -- see testscripts/test_fleet_upgrade.sh.
run_test "reclaim" reclaim_funds

summarize
[ $failed -eq 0 ]
