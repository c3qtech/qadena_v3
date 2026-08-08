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
#   credentials   update_credentials.sh                                    (--with-credentials)
#   replenish     al's ENCRYPTED balance is topped back up before anything spends it
#   peer-agreement   every peer computed the SAME app hash -- i.e. no fork
#   reclaim       the TRANSPARENT balance the suites accumulated goes back to the treasury
#   enclave-upgrade  a new enclave measurement takes over the sealed state (--with-enclave-upgrade)
#
# Everything except the genesis/chain/credentials layers is IDEMPOTENT -- safe to repeat against the
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
# Being repeatable is also not the same as being SUSTAINABLE: the suites drew about 7-9.4 million
# qdn per run from the treasury and never gave any of it back, which is a day and a half of running
# before a 2 billion qdn genesis treasury is gone.  The reclaim suite below returns most of it; see
# the note on reclaim_funds() for what no sweep can recover.
#
# TWO LAYERS ARE NOT REPEATABLE, and are therefore opt-in:
#
#   --from-genesis   DESTRUCTIVE.  init.sh deletes $QADENAHOME outright -- chain data AND the
#                    keyring.  Everything is rebuilt from config/config.yml.
#   --with-credentials  update_credentials.sh is single-shot: its claim codes are single-use and
#                    cases 1/2/5 consume rate-limit windows, so it cannot repeat against the same
#                    chain without editing the codes at the top of it.  Implied by --from-genesis,
#                    which produces a chain that has never run it.
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
#   regression.sh --with-credentials  also run the single-shot update_credentials.sh, last
#   regression.sh --with-enclave-upgrade  also upgrade the enclave to a new measurement, last
#   regression.sh --with-sgx          also verify the SGX build is signed and reproducible (SGX hw only)
#   regression.sh --stop-on-fail      stop at the first failure

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
advertise_ip=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --from-genesis)     from_genesis=true; shift ;;
        --with-setup)       with_setup=true; shift ;;
        --with-credentials) with_credentials=true; shift ;;
        --with-enclave-upgrade) with_enclave_upgrade=true; shift ;;
        --with-sgx)         with_sgx=true; shift ;;
        --stop-on-fail)     stop_on_fail=true; shift ;;
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
    # test_transfers.sh loses about 125qdn per run, so the floor is dozens of runs of headroom and
    # the top-up is hundreds -- this moves funds rarely rather than every run.
    local al_enc_floor=5000
    local al_enc_topup=50000
    local al_enc ann_enc

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

    ann_enc=$(enc_qdn ann)
    if [ -z "$ann_enc" ] || [ "$ann_enc" -lt "$al_enc_topup" ] 2>/dev/null; then
        echo "ann holds ${ann_enc:-?}qdn encrypted, not enough to move ${al_enc_topup}qdn to al"
        echo "al is below the floor and cannot be topped up, so the transfers suite would fail here"
        return 1
    fi

    echo "recycling ${al_enc_topup}qdn of encrypted balance from ann to al, via al-eph1"
    qadenad_alias tx qadena transfer-funds al-eph1 "${al_enc_topup}qdn" 0qdn \
        --transfer-note "regression replenish: returning al's encrypted float" --from ann --yes > /dev/null \
        || { echo "  ann could not transfer to al-eph1"; return 1; }

    # receive-funds takes one queued entry per call, and al-eph1 held nothing before this.
    qadenad_alias tx qadena receive-funds al-eph1 0qdn --from al --yes > /dev/null \
        || { echo "  al could not collect from al-eph1"; return 1; }

    al_enc=$(enc_qdn al)
    echo "al's encrypted balance now: ${al_enc}qdn"
    [ -n "$al_enc" ] && [ "$al_enc" -ge "$al_enc_floor" ] 2>/dev/null \
        || { echo "  al is still short after the recycle"; return 1; }
}

# RETURN WHAT THE SUITES BORROWED, so the treasury survives being run against repeatedly.
#
# A run costs the treasury far more than it destroys.  Measured over three consecutive runs on the
# two-node testnet: 9,407,832qdn drawn on a run that funded everything, 7,007,732qdn on one that did
# not need the evm top-up.  Almost all of it is still on the chain afterwards -- it has just moved
# into the accounts the suites transact with, and nothing was giving it back.  At that rate a
# 2,000,000,000qdn genesis treasury funds about 207 runs, which is a day and a half of running the
# suite back to back, and then every suite starts failing on insufficient funds at once.
#
# Two of the three big draws are already guarded ("top up al if short"), so they stop firing the
# moment al is solvent again.  Reclaiming is therefore enough on its own: put the transparent
# balance back and the guards go quiet.
#
# WHAT THIS DOES NOT YET RECOVER -- and it is a gap in this function, not a property of the chain.
#
# transfer-funds takes [from-encrypted-amount] [from-transparent-amount], and the large transfers in
# test_suspicious.sh spend the TRANSPARENT side to credit the recipient's ENCRYPTED balance.  This
# sweep only moves transparent balance, so what crossed over stays with ann and the transparent pool
# still shrinks by roughly 2.4 million qdn a run.
#
# It is RECOVERABLE, though.  receive-funds takes [to-transparent-amount], so collecting a transfer
# with an amount rather than the 0qdn every caller here passes brings it back out as transparent
# balance -- measured at exactly that, and asserted by case 10 of test_transfers.sh.  An earlier
# version of this comment claimed the opposite, that nothing unshields an encrypted balance and only
# --from-genesis could reset the pool; that was wrong, read off transfer-funds' signature and the Msg
# service without checking what receive-funds' second argument does.
#
# Closing it means routing ann's encrypted surplus back to al as transparent balance, which would
# stop the 5,000,000qdn top-up firing at all -- and per the per-run deltas that top-up IS the entire
# net drain.  Not done here yet.
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

    # ann is the one account that genuinely accumulates: it is the counterparty for the 2,000,000qdn
    # over-threshold send in test_bank_restriction.sh and for the evm suite's bank leg.  al is a net
    # SPENDER and is deliberately left alone -- refilling it is what the treasury guards are for, and
    # taking from it here would just make them fire again.  The per-run throwaway keys (bankscan-*,
    # evmsrc-*, evmdst-*) hold about 570qdn between them and are not worth enumerating.
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

        hash=$(echo "$result" | jq -r '.txhash' 2>/dev/null)
        [ -n "$hash" ] && [ "$hash" != "null" ] \
            || { echo "  no txhash from the send"; failures=$((failures + 1)); continue; }

        qadenad_alias query wait-tx "$hash" --timeout 30s > /dev/null 2>&1 \
            || { echo "  reclaim tx $hash did not land within 30s"; failures=$((failures + 1)); continue; }

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
    leftover=$(pgrep -af "qadenad|run_enclave.sh|run_signerenclave.sh|ego-host" 2>/dev/null | grep -v "regression.sh" || true)
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
run_test "dsvs"        "$qadenatestscripts/test_dsvs.sh"
run_test "wasm"        "$qadenatestscripts/test_wasm.sh"
run_test "evm"         "$qadenatestscripts/test_evm.sh"
run_test "cadena"      "$qadenatestscripts/test_cadena_contracts.sh"
run_test "enf"         "$qadenatestscripts/test_enf_contracts.sh"

# LAST of the always-on suites, and deliberately after everything that writes: a fork shows up in
# the app hash only once the suites have put transactions through.  Run early it would compare two
# idle nodes and pass regardless.
run_test "peer-agreement" "$qadenatestscripts/test_peer_agreement.sh"

# AFTER every suite that spends, and before the two opt-in ones.  The opt-in suites are excluded
# deliberately: --with-credentials runs once per chain and --with-enclave-upgrade stops the node,
# swaps the enclave binary and restarts it, so reclaiming after either would be transacting against
# a chain this run has just finished disturbing.  Neither is part of a repeat run, which is the case
# that needed the treasury back.
run_test "reclaim" reclaim_funds

if [ "$with_credentials" = "true" ]; then
    # LAST, because it mutates identities the other suites read: it removes al's email credential,
    # renames jill, and puts al/jill/dory inside their update cool-down windows.
    run_test "credentials" "$qadenatestscripts/update_credentials.sh"
fi

if [ "$with_enclave_upgrade" = "true" ]; then
    # LAST OF ALL, and after credentials.  It stops the node, swaps the enclave binary and restarts,
    # so anything after it would be measuring a different process; and it needs reports already on
    # record, which the suites above produce.
    run_test "enclave-upgrade" "$qadenatestscripts/test_enclave_upgrade.sh"
fi

summarize
[ $failed -eq 0 ]
