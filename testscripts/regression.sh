#!/bin/zsh
#
# Runs the whole regression suite and reports a summary.
#
# Covers every layer, from genesis construction to the credential flow:
#
#   genesis       buildscripts/init.sh, and the genesis it produces        (--from-genesis only)
#   chain         start the node and wait for blocks                       (--from-genesis only)
#   prerequisites providers, oracles and the create-wallet sponsor, onboarded at runtime
#   idempotency   prerequisites re-run, asserting it issues ZERO transactions
#   setup         the test users                                           (--with-setup)
#   pricefeed     oracle posting, per-market isolation, unregistered poster refused
#   pf-expiry     a posted price stops counting toward the median once it expires
#   transfers     transfer -> eph-wallet queue -> receive
#   suspicious    threshold scan, opt-in, and the regulator's report
#   dsvs          document signing hash chain
#   wasm          store / instantiate / execute
#   evm           deploy / read / write / overwrite
#   cadena        cadena-smart-contracts: the GAA -> PAP -> SARO -> NCA -> Obligation -> DV chain
#   enf           enf-smart-contracts: the ENF notarial book (ENP registry + entries)
#   credentials   update_credentials.sh                                    (--with-credentials)
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
#
# Usage:
#   regression.sh                     the repeatable suite against a running chain
#   regression.sh --from-genesis      wipe, rebuild, and run everything (implies the two below)
#   regression.sh --with-setup        run setup.sh first (slow; needed on a fresh chain)
#   regression.sh --with-credentials  also run the single-shot update_credentials.sh, last
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
stop_on_fail=false
advertise_ip=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --from-genesis)     from_genesis=true; shift ;;
        --with-setup)       with_setup=true; shift ;;
        --with-credentials) with_credentials=true; shift ;;
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
    while [ $i -lt 60 ]; do
        if curl -s http://localhost:26657/status 2>/dev/null | grep -q latest_block_height; then
            local h
            h=$(curl -s http://localhost:26657/status | jq -r '.result.sync_info.latest_block_height')
            if [ "${h:-0}" -gt 0 ] 2>/dev/null; then
                echo "chain producing blocks, height $h"
                return 0
            fi
        fi
        sleep 2
        i=$((i + 1))
    done
    echo "chain did not produce a block within 120s"
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

    run_test "genesis-init" "$qadenabuildscripts/init.sh" --advertise-ip-address "$advertise_ip"
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
run_test "suspicious"  "$qadenatestscripts/test_suspicious.sh"
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

summarize
[ $failed -eq 0 ]
