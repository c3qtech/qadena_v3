#!/bin/zsh
#
# Regression test for the Cadena budget-hierarchy contract (cadena-smart-contracts).
#
# Drives cadena_cli.sh `full`, which walks the whole chain of budget documents:
#
#   GAA -> PAP -> SARO -> NCA -> Obligation -> Disbursement Voucher
#
# and then asserts on the CONTRACT QUERIES.  Asserting on the queries rather than on the exit code
# is essential here, not stylistic: cadena_cli.sh `full` returns 0 even when a step inside it
# fails -- see the known defect below, which `full` reports nothing about.
#
# TWO CLI DEFECTS THIS SUITE EXISTS TO CATCH, both now fixed and asserted below:
#
#   create_disbursement omitted `disbursement_date`, the one non-Option field in
#   ExecuteMsg::CreateDisbursement, so every disbursement failed with
#       Error parsing into type cadena::msg::ExecuteMsg: missing field `disbursement_date`
#   leaving query-disbursements-by-dv empty and the recipient balance at zero.
#
#   get_disbursement_voucher sent a bare `id` where QueryMsg::GetDisbursementVoucher keys on all
#   three levels (obligation_id, nca_id, dv_id), so the DV could never be read back.
#
# Neither surfaced on its own because cadena_cli.sh `full` returns 0 regardless of what fails
# inside it -- which is exactly why every assertion here is on a contract query.
#
# Idempotent: `clean` drops the state file and each run uploads and instantiates a FRESH contract,
# so the hierarchy always starts empty and the counts below are absolute rather than deltas.
#
# Run AFTER testscripts/setup.sh.  `full` provisions its own DBM account on first use (idempotently)
# against testidentitysrvprv, pioneer1 and create-wallet-sponsor -- all present once
# setup_prerequisites.sh has run.

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

set -e

function qadenad_alias { "$qadenabin/qadenad" --home "$QADENAHOME" "$@" }

cadenadir="$qadenabuild/cadena-smart-contracts"
cli="$cadenadir/cadena_cli.sh"
gaa_id="gaa_2025"

fail() {
    echo "FAILED: $1"
    exit 1
}

# cadena_cli wraps its JSON in a banner before and a "Query completed successfully!" line after, so
# take exactly the first top-level object: from the first line that is "{" to the first line that
# is "}".  Taking everything from the first brace to EOF picks up the trailing line and jq fails
# with "Invalid numeric literal".
cadena_json() {
    "$cli" "$@" 2>/dev/null | sed -n '/^{$/,/^}$/p'
}

echo "========================="
echo "preflight"
echo "========================="
qadenad_alias status > /dev/null 2>&1 || fail "chain is not reachable -- start it first"
[ -x "$cli" ] || fail "missing $cli"
[ -f "$cadenadir/artifacts/cadena.wasm" ] || fail "missing the built contract artifact"
[ -f "$cadenadir/cw20_base.wasm" ] || fail "missing cw20_base.wasm (the GAA token contract)"
qadenad_alias query wasm params > /dev/null 2>&1 || fail "the wasm module is not responding"
qadenad_alias keys show testidentitysrvprv -a --keyring-backend test > /dev/null 2>&1 \
    || fail "testidentitysrvprv missing -- run testscripts/setup_prerequisites.sh first"
echo "chain up, artifacts present"

echo "========================="
echo "1. run the full budget hierarchy flow"
echo "========================="
# `clean` forces a fresh contract; without it the flow would append to a previous run's hierarchy
# and the counts asserted below would drift upward each time.
"$cli" clean > /dev/null 2>&1 || true

# NOTE: the exit code here is nearly meaningless -- see the header.  It is checked only to catch a
# total failure to run; the real verdict is the queries that follow.
"$cli" full > /dev/null 2>&1 || fail "cadena_cli.sh full did not run to completion"
echo "flow completed"

echo "========================="
echo "2. the GAA exists and is the root of the hierarchy"
echo "========================="
gaas=$(cadena_json query-gaas)
total=$(echo "$gaas" | jq -r '.data.total // 0')
[ "$total" = "1" ] || fail "expected exactly 1 GAA on a fresh contract, got $total"

echo "$gaas" | jq -r '.data.gaas[0] | {id, year, total_amount, status, pap_count}'
[ "$(echo "$gaas" | jq -r '.data.gaas[0].id')"     = "$gaa_id" ] || fail "GAA id is not $gaa_id"
[ "$(echo "$gaas" | jq -r '.data.gaas[0].status')" = "Active" ] || fail "GAA is not Active"

# a GAA mints a CW20 token to carry its budget; without it the hierarchy has nothing to allocate
token=$(echo "$gaas" | jq -r '.data.gaas[0].token_address')
[ -n "$token" ] && [ "$token" != "null" ] || fail "the GAA has no token contract address"
echo "GAA token contract: $token"

# the GAA must have recorded the PAP created under it
pap_count=$(echo "$gaas" | jq -r '.data.gaas[0].pap_count // 0')
[ "$pap_count" -ge 1 ] || fail "the GAA reports $pap_count PAPs, expected at least 1"

echo "========================="
echo "3. the PAP is queryable under its GAA"
echo "========================="
paps=$(cadena_json query-paps "$gaa_id")
n=$(echo "$paps" | jq -r '.data.total // (.data.paps | length) // 0')
[ "${n:-0}" -ge 1 ] || fail "no PAPs found under $gaa_id"
echo "$paps" | jq -r '.data.paps[0] | {id, amount}' 2>/dev/null || true
echo "$n PAP(s) under $gaa_id"

echo "========================="
echo "4. the whole allocation chain is present in the hierarchy"
echo "========================="
# One query walks GAA -> PAP -> SARO -> NCA -> Obligation -> DV.  Each document validates against
# its parent when created, so finding the DV at the bottom proves every step above it landed --
# a stronger statement than querying the documents individually, and it sidesteps the broken
# query-disbursement-voucher command.
hier=$(cadena_json query-hierarchy "$gaa_id")
[ -n "$hier" ] || fail "query-hierarchy returned nothing"

chain=$(echo "$hier" | jq -r '{
  gaa:         .data.gaa.id,
  paps:        [.data.paps[]?.pap.id],
  saros:       [.. | objects | select(has("saro_number"))       | .saro_number]       | unique,
  ncas:        [.. | objects | select(has("nca_number"))        | .nca_number]        | unique,
  obligations: [.. | objects | select(has("obligation_number")) | .obligation_number] | unique,
  dvs:         [.. | objects | select(has("dv_number"))         | .dv_number]         | unique
}') || fail "could not parse the hierarchy"
echo "$chain"

[ "$(echo "$chain" | jq -r '.gaa')" = "$gaa_id" ] || fail "the hierarchy is not rooted at $gaa_id"
for level in paps saros ncas obligations dvs; do
    n=$(echo "$chain" | jq -r --arg l "$level" '.[$l] | length')
    [ "${n:-0}" -ge 1 ] || fail "the hierarchy contains no $level; the allocation chain broke above that level"
done
echo "GAA -> PAP -> SARO -> NCA -> Obligation -> DV all present"

echo "========================="
echo "5. the disbursement voucher reads back through its own query"
echo "========================="
# Regression guard: this query used to fail outright with
#   unknown field `id`, expected one of `obligation_id`, `nca_id`, `dv_id`
dv=$(cadena_json query-disbursement-voucher)
dv_id=$(echo "$dv" | jq -r '.data.id // empty')
[ -n "$dv_id" ] || fail "query-disbursement-voucher returned no DV; the query fields have drifted again"
echo "$dv" | jq -r '.data | {id, dv_number, amount, payee}'

echo "========================="
echo "6. a disbursement is created and recorded against the DV"
echo "========================="
# Regression guard: create_disbursement used to fail on the missing disbursement_date, silently,
# because `full` swallows the error.  Asserting the RECORD rather than the exit code.
#
# OUTPUT IS KEPT, not discarded.  `> /dev/null 2>&1` here threw away the only description of what
# went wrong, and when the disbursement stopped being broadcast the suite reported nothing at all --
# it simply stopped, because the CLI then waited on an empty transaction hash forever.  Diagnosing
# it needed the chain, the process table and a manual replay.  The text was there all along.
disb_out=$("$cli" disbursement-only 2>&1) || {
    echo "$disb_out" | tail -20
    fail "disbursement-only failed"
}

disb=$(cadena_json query-disbursements-by-dv)
total=$(echo "$disb" | jq -r '.data.total // 0')
[ "${total:-0}" -ge 1 ] \
    || fail "no disbursements recorded against $dv_id; create_disbursement is failing again"
echo "$disb" | jq -r '.data | {total, count}'
echo "disbursement recorded against $dv_id"

echo "========================="
echo "CADENA CONTRACT TESTS PASSED"
echo "========================="
