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
#   setup         the test users                                           (--with-setup)
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
#   credentials   update_credentials.sh -- corrections, rejections, contacts, anti-squat
#                 (its single-shot KEY RECOVERY cases additionally need --with-credentials)
#   replenish     al's ENCRYPTED balance is topped back up before anything spends it
#   peer-agreement   every peer computed the SAME app hash -- i.e. no fork
#   reclaim       the TRANSPARENT balance the suites accumulated goes back to the treasury
#   enclave-upgrade  a new enclave measurement takes over the sealed state (--with-enclave-upgrade)
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
# TWO LAYERS ARE NOT REPEATABLE, and are therefore opt-in:
#
#   --from-genesis   DESTRUCTIVE.  init.sh deletes $QADENAHOME outright -- chain data AND the
#                    keyring.  Everything is rebuilt from config/config.yml.
#   --with-credentials  NO LONGER GATES THE CREDENTIALS SUITE, which now runs by default: it
#                    provisions its own four identities per run with setup.sh --prefix, so the
#                    single-use claim codes and the 10000-block update cool-down that made it
#                    single-shot no longer apply.  The flag now adds only the KEY RECOVERY cases
#                    inside it, which remain genuinely once-per-chain -- a wallet may be recovered
#                    exactly ONCE (getRecoverKeyByOriginalWalletID refuses a second) and the
#                    partner approvals need three signatories resolved three different ways, i.e.
#                    the whole seeded user set.  Implied by --from-genesis.
#   --with-enclave-upgrade  registers a new enclave identity on chain PERMANENTLY, then stops the
#                    node, swaps the enclave binary and restarts.  Runs last, after credentials,
#                    because nothing after it would be measuring the same process -- and because it
#                    needs reports already on record to prove the migrated keys still read them.
#                    NOT implied by --from-genesis: it is slow and leaves the chain on a new enclave.
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
#   regression.sh --from-genesis      wipe, rebuild, and run everything (implies the two below)
#   regression.sh --with-setup        run setup.sh first (slow; needed on a fresh chain)
#   regression.sh --with-credentials  also run the single-shot key-recovery cases in credentials
#   regression.sh --with-enclave-upgrade  also upgrade the enclave to a new measurement, last
#   regression.sh --with-sgx          also verify the SGX build is signed and reproducible (SGX hw only)
#   regression.sh --stop-on-fail      stop at the first failure
#   regression.sh --skip a,b,c        do not run these suites
#
# --skip exists for runs that must not lose the chain.  enclave-rollback, enclave-crash and
# enclave-upgrade STOP AND RESTART the node by design, which is correct when the suite is the only
# thing using it and disastrous when it is not: a joining node sees the primary's RPC vanish for
# minutes, and snapshot accumulation restarts.  For a continuous run alongside a second node, use
#   --skip enclave-rollback,enclave-crash,enclave-upgrade

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

# NOTE: no `set -e` here.  This script's job is to run every test and report, so a failing test must
# not abort the runner.  Each test script has its own set -e.

function qadenad_alias { "$qadenabin/qadenad" --home "$QADENAHOME" "$@" }

from_genesis=false
with_setup=false
with_credentials=false
with_enclave_upgrade=false
with_sgx=false
stop_on_fail=false
skip_list=""
advertise_ip=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --from-genesis)     from_genesis=true; shift ;;
        --with-setup)       with_setup=true; shift ;;
        --with-credentials) with_credentials=true; shift ;;
        --with-enclave-upgrade) with_enclave_upgrade=true; shift ;;
        --with-sgx)         with_sgx=true; shift ;;
        --stop-on-fail)     stop_on_fail=true; shift ;;
        --skip)             skip_list="$2"; shift 2 ;;
        --advertise-ip-address) advertise_ip="$2"; shift 2 ;;
        --help)
            sed -n '/^# Usage:/,/^$/p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) echo "Unknown option: $1"; echo "try: $0 --help"; exit 1 ;;
    esac
done

# a chain built from genesis has never seen any of it, so both of these become available
if [ "$from_genesis" = "true" ]; then
    with_setup=true
    with_credentials=true
fi

logdir="$qadenabuild/logs/regression"
mkdir -p "$logdir"

names=()
results=()
seconds=()
failed=0

# run_test <label> <command> [args...]
run_test() {
    local label="$1"; shift

    # SKIPPED IS RECORDED, NOT SILENT.  A suite that vanishes from the summary is indistinguishable
    # from one that passed, and this runner's whole value is that its output means something.
    if [[ -n "$skip_list" ]] && print -r -- ",$skip_list," | grep -q ",$label,"; then
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
# because the enclave-upgrade suite makes a temporary commit, inside .git itself.  The next plain
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
    # scanned, and the enclave does not exist yet: delayed_init_enclave.sh waits for height 4 before
    # running InitEnclave.  Returning early therefore handed the next suite a chain that answers
    # every query and refuses every send.
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
    # stop_qadena.sh that could not kill a run_enclave.sh respawn loop: the loop kept restarting a
    # DEBUG enclave, is_qadena_running stayed true, and start_qadena.sh then reported "already
    # running" and never launched the chain.  The run failed 25 minutes later with "chain did not
    # produce a block within 120s", naming nothing that had gone wrong.
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
        | grep -E "qadenad|run_enclave\.sh|run_signerenclave\.sh|ego-host" \
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

if [ "$with_setup" = "true" ]; then
    run_test "setup" "$qadenatestscripts/setup.sh"
else
    if ! qadenad_alias keys show al -a --keyring-backend test > /dev/null 2>&1; then
        echo ""
        echo "FAILED: the test users do not exist (al is missing)."
        echo "  run:  $0 --with-setup"
        summarize
        exit 1
    fi
    echo "test users present (skipping setup.sh; use --with-setup to force)"
fi

# BEFORE the suites that spend, so al is solvent in both pools when they start.
run_test "replenish"   replenish_funds

run_test "pricefeed"   "$qadenatestscripts/test_pricefeed.sh"
run_test "pf-expiry"   "$qadenatestscripts/test_pricefeed_expiry.sh"
run_test "transfers"   "$qadenatestscripts/test_transfers.sh"
if [ "$with_sgx" = "true" ]; then
    # FIRST among the functional suites, for two reasons.  A broken or non-reproducible SGX build
    # should fail before an hour of chain tests runs on top of it; and it must come before
    # enclave-upgrade, which leaves the installed enclave at a measurement NEWER than the committed
    # source -- a --build-sgx after that would install the older measurement as main and the node
    # would then find no sealed params matching it.
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
# --with-credentials no longer gates it; it now only adds the single-shot KEY RECOVERY cases (6,
# 6a, 6b) inside it, which genuinely cannot repeat -- a wallet may be recovered exactly ONCE,
# permanently, and their partner approvals need three signatories resolved three different ways,
# which is the whole seeded user set rather than the four this suite provisions.  Implied by
# --from-genesis, so a fresh chain still gets that coverage, including the hash-aliasing case that
# is the only test anywhere of recovery via a PRE-MARRIAGE surname.
if [ "$with_credentials" = "true" ]; then
    export UPDATE_CREDENTIALS_WITH_RECOVERY=1
fi
run_test "credentials" "$qadenatestscripts/update_credentials.sh"
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

# AFTER every suite that spends, and before the two opt-in ones.  The opt-in suites are excluded
# deliberately: --with-credentials runs once per chain and --with-enclave-upgrade stops the node,
# swaps the enclave binary and restarts it, so reclaiming after either would be transacting against
# a chain this run has just finished disturbing.  Neither is part of a repeat run, which is the case
# that needed the treasury back.
run_test "reclaim" reclaim_funds


if [ "$with_enclave_upgrade" = "true" ]; then
    # LAST OF ALL, and after credentials.  It stops the node, swaps the enclave binary and restarts,
    # so anything after it would be measuring a different process; and it needs reports already on
    # record, which the suites above produce.
    run_test "enclave-upgrade" "$qadenatestscripts/test_enclave_upgrade.sh"
fi

summarize
[ $failed -eq 0 ]
