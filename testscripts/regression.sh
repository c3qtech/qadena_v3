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
#   enclave-upgrade  a new enclave measurement takes over the sealed state (--with-enclave-upgrade)
#
# Everything except the genesis/chain/credentials layers is IDEMPOTENT -- safe to repeat against the
# same chain.  They achieve that in different ways depending on what the module allows: delta
# assertions rather than absolute balances (transfers), per-run unique ids AND content (dsvs -- a
# document is keyed by content hash, so unique ids alone are not enough), fresh deploys (evm, wasm),
# top-up only when short (suspicious), end-state guards rather than "did I run before"
# (prerequisites).
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

    echo "running init.sh as $SUDO_USER (it refuses to run as root), home $user_home"
    sudo -u "$SUDO_USER" env -u SUDO_USER "HOME=$user_home" "$qadenabuildscripts/init.sh" "$@"
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
    "$qadenascripts/stop_qadena.sh" > /dev/null 2>&1
    sleep 2

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
