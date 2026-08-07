#!/bin/zsh
#
# Regression test for the ENF Electronic Notarial Book contract (enf-smart-contracts).
#
# Drives enf_cli.sh: upload -> instantiate -> register an ENP -> update it -> create an entry, and
# asserts on the CONTRACT QUERIES rather than on exit codes.  The CLI reports success for a tx it
# broadcast, which is not the same as the contract having stored what was intended.
#
# TWO CLI COMMANDS ARE DELIBERATELY SKIPPED:
#
#   setup-enf      creates the ENF deployer via create_user.sh against enfidentitysrvprv, an
#                  identity provider this chain does not have -- only testidentitysrvprv and
#                  testdsvssrvprv are onboarded.  Signing with an existing funded key via -k
#                  reaches the same contract behaviour without it.
#   setup-backend  registers the contract with the ENF API on :3002.  Out of scope here: this
#                  tests the contract, not the backend.
#
# Idempotent: `clean` drops the state file and every run uploads and instantiates a FRESH contract,
# so the ENP registry always starts empty and the assertions below are absolute rather than deltas.
#
# Run AFTER testscripts/setup.sh (it needs a funded signer).

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

set -e

function qadenad_alias { "$qadenabin/qadenad" --home "$QADENAHOME" "$@" }

enfdir="$qadenabuild/enf-smart-contracts"
cli="$enfdir/enf_cli.sh"
signer="${ENF_TEST_SIGNER:-al}"

roll="12345"
email="enp@example.com"
name="Atty. Jane Cruz"
commission="2024-001"

new_email="jane.cruz@example.com"
new_commission="2026-009"
changed_by="enf-admin@example.com"

entry_id="entry-1"

fail() {
    echo "FAILED: $1"
    exit 1
}

# enf_cli prints the setup_env banner before its JSON, so take only from the first brace onward
enf_json() {
    "$cli" -k "$signer" "$@" 2>/dev/null | sed -n '/^{/,$p'
}

# run_cli <label> <args...> -- quiet on success, and on failure prints WHAT WENT WRONG.
#
# These used to be `"$cli" ... > /dev/null 2>&1 || fail "instantiate failed"`, which discarded the
# only copy of the error.  A regression run then reported exactly "FAILED: instantiate failed" with
# no raw_log, no tx hash and no code -- and since the tx is gone by the time anyone reads the log,
# there is nothing left to investigate afterwards.  The output is suppressed on success because the
# CLI is noisy; suppressing it on FAILURE is what cost the diagnosis.
run_cli() {
    local label="$1"; shift
    local out
    if ! out=$("$cli" -k "$signer" "$@" 2>&1); then
        echo "--- $label failed, output follows ---"
        echo "$out"
        echo "--- end of $label output ---"
        fail "$label failed"
    fi
    # A tx can be broadcast successfully and still be rejected on chain, in which case the CLI exits
    # 0 with a non-zero code in its JSON.  Catch that here rather than three assertions later.
    # Anchored, because a loose /code.*[1-9]/ also matches "Saved code_id: 7" and would fail every
    # successful upload.  Only the two forms cosmos actually prints for a result code count.
    if echo "$out" | grep -qE '^ *"?code"?: *"?[1-9]|UNCONFIRMED'; then
        echo "--- $label reported a failure despite exiting 0 ---"
        echo "$out"
        fail "$label was not confirmed on chain"
    fi
}

echo "========================="
echo "preflight"
echo "========================="
qadenad_alias status > /dev/null 2>&1 || fail "chain is not reachable -- start it first"
[ -x "$cli" ] || fail "missing $cli"
[ -f "$enfdir/artifacts/enf_notarial_book.wasm" ] || fail "missing the built contract artifact"
qadenad_alias keys show "$signer" -a --keyring-backend test > /dev/null 2>&1 \
    || fail "signer '$signer' not in the keyring -- run testscripts/setup.sh, or set ENF_TEST_SIGNER"
qadenad_alias query wasm params > /dev/null 2>&1 || fail "the wasm module is not responding"
echo "chain up, signing as $signer"

echo "========================="
echo "1. deploy a fresh contract"
echo "========================="
"$cli" clean > /dev/null 2>&1 || true
run_cli "upload" upload
run_cli "instantiate" instantiate

addr=$("$cli" -k "$signer" contract-addr 2>/dev/null | grep -oE 'qadena1[a-z0-9]+' | tail -1)
[ -n "$addr" ] || fail "no contract address after instantiate"
echo "contract: $addr"

# a fresh instance must start with an empty registry -- otherwise the assertions below could be
# satisfied by state left behind from an earlier run
count=$(enf_json get-count | jq -r '.data.count // .data // empty')
echo "entries at deploy: ${count:-0}"
[ "${count:-0}" = "0" ] || fail "a freshly instantiated contract already reports $count entries"

echo "========================="
echo "2. register an ENP and read it back"
echo "========================="
run_cli "register-enp" register-enp "$roll" "$email" "$name" "$commission"

got=$(enf_json get-enp "$roll")
echo "$got" | jq -r '.data | {roll_number, email, full_name, commission_number, change_count}'

[ "$(echo "$got" | jq -r '.data.roll_number')"      = "$roll" ]       || fail "roll_number mismatch"
[ "$(echo "$got" | jq -r '.data.email')"            = "$email" ]      || fail "email mismatch"
[ "$(echo "$got" | jq -r '.data.full_name')"        = "$name" ]       || fail "full_name mismatch"
[ "$(echo "$got" | jq -r '.data.commission_number')" = "$commission" ] || fail "commission mismatch"
[ "$(echo "$got" | jq -r '.data.change_count')"     = "0" ]           || fail "a new ENP should have change_count 0"
echo "stored exactly what was registered"

echo "========================="
echo "3. look the ENP up by its secondary indexes"
echo "========================="
# registering must populate the email and commission indexes, not just the primary roll key
by_email=$(enf_json get-enp-by-email "$email" | jq -r '.data.roll_number // empty')
[ "$by_email" = "$roll" ] || fail "get-enp-by-email returned '$by_email', expected $roll"
by_comm=$(enf_json get-enp-by-commission "$commission" | jq -r '.data.roll_number // empty')
[ "$by_comm" = "$roll" ] || fail "get-enp-by-commission returned '$by_comm', expected $roll"
echo "email and commission indexes both resolve to $roll"

echo "========================="
echo "4. update the ENP -- the change must be recorded, not just applied"
echo "========================="
run_cli "update-enp" update-enp "$roll" "$new_email" "$name" "$new_commission" "$changed_by"

got=$(enf_json get-enp "$roll")
[ "$(echo "$got" | jq -r '.data.email')"             = "$new_email" ]      || fail "email was not updated"
[ "$(echo "$got" | jq -r '.data.commission_number')" = "$new_commission" ] || fail "commission was not updated"
[ "$(echo "$got" | jq -r '.data.change_count')"      = "1" ]               || fail "change_count did not increment"
echo "updated, change_count now 1"

# an audit trail is the point of a notarial register: the previous values must remain retrievable
changes=$(enf_json get-enp-changes "$roll")
n=$(echo "$changes" | jq -r '(.data.changes // .data) | length')
[ "${n:-0}" -ge 1 ] || fail "no change history recorded for $roll"
echo "$changes" | jq -r '(.data.changes // .data)[0] | {changed_by}' 2>/dev/null || true
echo "$n change record(s) retained"

echo "========================="
echo "5. create a notarial entry and read it back"
echo "========================="
run_cli "create-entry" create-entry "$entry_id" "$roll"

entry=$(enf_json get-entry "$entry_id")
[ "$(echo "$entry" | jq -r '.data.id')" = "$entry_id" ] || fail "get-entry did not return $entry_id"
echo "$entry" | jq -r '.data | {id, status, document_title}'

count=$(enf_json get-count | jq -r '.data.count // .data // empty')
[ "${count:-0}" = "1" ] || fail "expected 1 entry after create-entry, got ${count:-0}"

listed=$(enf_json get-entries | jq -r '(.data.entries // .data) | length')
[ "${listed:-0}" -ge 1 ] || fail "get-entries returned nothing after create-entry"
echo "entry stored, count 1, and it appears in get-entries"

echo "========================="
echo "ENF CONTRACT TESTS PASSED"
echo "========================="
