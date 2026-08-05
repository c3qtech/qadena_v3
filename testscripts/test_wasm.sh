#!/bin/zsh
#
# Regression test for CosmWasm: store -> instantiate -> execute, and the fund movement the bank
# send restriction now refuses.
#
# WHAT CHANGED AND WHY.  This suite used to instantiate hackatom holding 1qdn and then execute
# {"release":{}} to pay a beneficiary, asserting the balance moved.  Both of those legs go through
# bank's SendCoins -- wasmd funds a contract with TransferCoins at instantiate and execute, and a
# contract's payout is dispatched as a bank MsgSend -- so both are now caught by the AML send
# restriction.  A contract address is not a module account, is not whitelisted, and holds no
# credential, so neither leg can be scanned and neither is allowed.
#
# The consequence is a product fact worth stating plainly: CONTRACTS CANNOT CUSTODY FUNDS ON THIS
# CHAIN.  That is asserted below rather than left to be discovered.  The plumbing coverage that made
# the old suite worth having -- store, instantiate, execute through the qadena wrapper -- is kept,
# just at zero value.
#
# HOW FAILURES SURFACE.  The scan is skipped in CheckTx and simulation, so a refused message
# broadcasts cleanly, gets a hash, and fails inside the block.  `tx qadena execute-wasm` prints the
# failure but STILL EXITS 0 -- the old suite's `|| fail` could not have caught this.  Every verdict
# below therefore comes from the transaction's on-chain result code, never from an exit status.
#
# Idempotent: accounts are created only if missing and topped up only if empty, and each run stores
# and instantiates its own contract under a per-run label.
#
# Run AFTER testscripts/setup.sh.

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

set -e

function qadenad_alias { "$qadenabin/qadenad" --home "$QADENAHOME" "$@" }

cd $qadenabuild

wasm_file="$qadenatestdata/hackatom.wasm"
run_id=$(date +%s)
label="regression-$run_id"
funder="treasury"
send_amount="1qdn"
account_funding="20qdn"

gas_flags=(--gas $gas_auto --gas-adjustment $gas_adjustment --gas-prices $minimum_gas_prices)

fail() {
    echo "FAILED: $1"
    exit 1
}

bank_aqdn() {
    local amt
    amt=$(qadenad_alias query bank balances "$1" --output json 2>/dev/null \
        | jq -r '.balances[] | select(.denom=="aqdn") | .amount' 2>/dev/null | head -1) || amt=""
    echo "${amt:-0}"
}

qdn() { python3 -c "print(int('${1:-0}')/10**18)"; }

# run_tx <cmd...> -- broadcast, wait, and set tx_code / tx_log from the ON-CHAIN result.
#
# The broadcast response only says the transaction entered the mempool; the scan runs later, during
# execution, so the broadcast code is always 0 and tells us nothing.  stdout is taken alone because
# --gas auto writes "gas estimate: N" to stderr, and folding that into the JSON makes jq fail on
# every call -- which under `set -e` kills the script with no message at all.
run_tx() {
    local out hash
    tx_code=""; tx_log=""
    out=$("$@" 2>/dev/null) || { tx_code="BROADCAST_REJECTED"; tx_log="$out"; return 0; }
    hash=$(echo "$out" | jq -r '.txhash' 2>/dev/null)
    if [ -z "$hash" ] || [ "$hash" = "null" ]; then
        tx_code="NO_TXHASH"; tx_log="$out"; return 0
    fi
    qadenad_alias query wait-tx "$hash" --timeout 60s > /dev/null 2>&1 || true
    tx_code=$(qadenad_alias query tx "$hash" --output json 2>/dev/null | jq -r '.code // "UNKNOWN"')
    tx_log=$(qadenad_alias query tx "$hash" --output json 2>/dev/null | jq -r '.raw_log // ""')
}

contract_count() {
    qadenad_alias query wasm list-contract-by-code "$1" --output json 2>/dev/null \
        | jq -r '.contracts | length'
}

# create the account if missing, fund it if empty -- guarded separately so a run that died between
# the two does not leave an unfunded key that the next run skips over.  Funding works because the
# sender is treasury, which is whitelisted; alice could not fund anyone this way.
ensure_account() {
    local name="$1" addr
    if ! qadenad_alias keys show "$name" --keyring-backend test > /dev/null 2>&1; then
        qadenad_alias keys add "$name" --keyring-backend test > /dev/null 2>&1 \
            || fail "could not create $name"
    fi
    addr=$(qadenad_alias keys show "$name" -a --keyring-backend test)
    if [ "$(bank_aqdn "$addr")" = "0" ]; then
        run_tx qadenad_alias tx bank send "$funder" "$addr" "$account_funding" \
            --from "$funder" --yes --output json "${gas_flags[@]}"
        [ "$tx_code" = "0" ] || fail "could not fund $name (code $tx_code)"
        [ "$(bank_aqdn "$addr")" != "0" ] || fail "$name still has no balance after funding"
    fi
}

echo "========================="
echo "preflight"
echo "========================="
qadenad_alias status > /dev/null 2>&1 || fail "chain is not reachable -- start it first"
[ -f "$wasm_file" ] || fail "missing $wasm_file"
qadenad_alias keys show "$funder" -a --keyring-backend test > /dev/null 2>&1 \
    || fail "$funder not in the keyring"
qadenad_alias query wasm params > /dev/null 2>&1 || fail "the wasm module is not responding"

ensure_account alice
ensure_account bob
alice_addr=$(qadenad_alias keys show alice -a --keyring-backend test)
bob_addr=$(qadenad_alias keys show bob -a --keyring-backend test)
echo "chain up, wasm responding"
echo "alice (verifier):   $alice_addr  $(qdn "$(bank_aqdn "$alice_addr")")qdn"
echo "bob (beneficiary):  $bob_addr  $(qdn "$(bank_aqdn "$bob_addr")")qdn"

echo "========================="
echo "1. store the contract"
echo "========================="
run_tx qadenad_alias tx wasm store "$wasm_file" --from alice --yes --output json "${gas_flags[@]}"
[ "$tx_code" = "0" ] || fail "tx wasm store failed with code $tx_code: $tx_log"

# a fresh code id per run, so the contract counts below start from zero and can be compared
code_id=$(qadenad_alias query wasm list-code --output json 2>/dev/null \
    | jq -r '.code_infos[-1].code_id')
[ -n "$code_id" ] && [ "$code_id" != "null" ] || fail "no code id after store"
echo "code id: $code_id"

echo "========================="
echo "2. a zero-value instantiate works"
echo "========================="
# Storing code and creating an instance move no funds, so nothing here touches bank at all.
init="{\"verifier\":\"$alice_addr\",\"beneficiary\":\"$bob_addr\"}"
run_tx qadenad_alias tx wasm instantiate "$code_id" "$init" \
    --admin "$alice_addr" --label "$label" \
    --from alice --yes --output json "${gas_flags[@]}"
[ "$tx_code" = "0" ] || fail "a zero-value instantiate failed with code $tx_code: $tx_log"

contract_addr=$(qadenad_alias query wasm list-contract-by-code "$code_id" --output json 2>/dev/null \
    | jq -r '.contracts[-1]')
[ -n "$contract_addr" ] && [ "$contract_addr" != "null" ] \
    || fail "no contract address for code id $code_id"
echo "contract: $contract_addr"

qadenad_alias query wasm contract "$contract_addr" --output json > /dev/null 2>&1 \
    || fail "the instantiated contract is not queryable"
[ "$(bank_aqdn "$contract_addr")" = "0" ] \
    || fail "a zero-value instantiate left the contract holding funds"
echo "contract queryable and holding nothing"

echo "========================="
echo "3. a zero-value execute works, through the qadena wrapper"
echo "========================="
# `tx qadena execute-wasm` is the path this chain actually uses, so it is the one worth covering.
# It waits for the result and PRINTS the failure, but exits 0 either way -- so the output is
# searched for the failure text and the on-chain code is checked as well.
#
# release on an empty contract is a no-op payout, which is exactly what makes it usable here: it
# exercises the full execute path without asking bank to move anything.
out=$(qadenad_alias tx qadena execute-wasm "$contract_addr" '{"release":{}}' \
    --from alice --yes "${gas_flags[@]}" 2>&1) || true
# `grep -q ... && fail` would be wrong here: when grep finds nothing the whole list exits non-zero
# and `set -e` kills the script at the point where the test actually PASSED
if echo "$out" | grep -q "failed with"; then
    fail "a zero-value execute was rejected: $(echo "$out" | grep 'failed with' | head -1)"
fi
exec_hash=$(echo "$out" | grep -o 'txhash: [A-F0-9]*' | head -1 | awk '{print $2}')
[ -n "$exec_hash" ] || fail "could not read the txhash from execute-wasm's output"
qadenad_alias query wait-tx "$exec_hash" --timeout 60s > /dev/null 2>&1 || true
exec_code=$(qadenad_alias query tx "$exec_hash" --output json 2>/dev/null | jq -r '.code // "UNKNOWN"')
[ "$exec_code" = "0" ] || fail "the zero-value execute landed with code $exec_code"
echo "executed through qadena execute-wasm"

echo "========================="
echo "4. instantiating WITH funds is refused"
echo "========================="
# wasmd moves the deposit creator -> contract through SendCoins.  alice is an ordinary key, the
# contract holds no credential, so the send cannot be scanned and the whole transaction reverts.
alice_before=$(bank_aqdn "$alice_addr")
before_count=$(contract_count "$code_id")
run_tx qadenad_alias tx wasm instantiate "$code_id" "$init" \
    --admin "$alice_addr" --label "$label-funded" --amount "$send_amount" \
    --from alice --yes --output json "${gas_flags[@]}"
[ "$tx_code" != "0" ] || fail "instantiating with $send_amount was allowed; the restriction is not covering wasmd"
echo "$tx_log" | grep -q "code 1159" \
    || { echo "$tx_log" | head -2; fail "expected qadena code 1159 (not scannable), got the above"; }
[ "$(contract_count "$code_id")" = "$before_count" ] \
    || fail "a refused instantiate still created a contract"
# only fees left alice; the deposit did not
python3 -c "
raise SystemExit(0 if int('$alice_before') - int('$(bank_aqdn "$alice_addr")') < 10**18 else 1)
" || fail "alice lost at least $send_amount on a refused instantiate"
echo "refused (qadena code 1159), no contract created, no funds moved"

echo "========================="
echo "5. executing WITH funds is refused"
echo "========================="
# Same leg, at execute time rather than instantiate time.
alice_before=$(bank_aqdn "$alice_addr")
run_tx qadenad_alias tx wasm execute "$contract_addr" '{"release":{}}' --amount "$send_amount" \
    --from alice --yes --output json "${gas_flags[@]}"
[ "$tx_code" != "0" ] || fail "executing with $send_amount attached was allowed"
echo "$tx_log" | grep -q "code 1159" \
    || { echo "$tx_log" | head -2; fail "expected qadena code 1159, got the above"; }
[ "$(bank_aqdn "$contract_addr")" = "0" ] || fail "a refused execute still funded the contract"
echo "refused (qadena code 1159), the contract still holds nothing"

echo "========================="
echo "6. a contract that somehow holds funds can never pay them out"
echo "========================="
# A whitelisted sender is exempt, and the exemption is on the SENDER only -- so treasury can push
# funds into a contract even though no ordinary account can.  The contract itself is not exempt, so
# its payout is refused.  Funds that reach a contract this way are stuck there permanently.
#
# This is a hazard, not a feature: WHITELISTED ACCOUNTS MUST NOT SEND TO CONTRACT ADDRESSES.  It is
# asserted here so that the day the payout rule changes, this test says so.
run_tx qadenad_alias tx bank send "$funder" "$contract_addr" "$send_amount" \
    --from "$funder" --yes --output json "${gas_flags[@]}"
[ "$tx_code" = "0" ] \
    || fail "a whitelisted sender could not fund the contract (code $tx_code); case 6 assumes it can"
contract_held=$(bank_aqdn "$contract_addr")
[ "$contract_held" != "0" ] || fail "the contract holds nothing after treasury funded it"
echo "treasury funded the contract with $(qdn "$contract_held")qdn (whitelisted sender)"

bob_before=$(bank_aqdn "$bob_addr")
run_tx qadenad_alias tx wasm execute "$contract_addr" '{"release":{}}' \
    --from alice --yes --output json "${gas_flags[@]}"
[ "$tx_code" != "0" ] || fail "the contract paid out; a contract payout must be refused"
echo "$tx_log" | grep -q "code 1159" \
    || { echo "$tx_log" | head -2; fail "expected qadena code 1159 on the payout, got the above"; }
[ "$(bank_aqdn "$bob_addr")" = "$bob_before" ] || fail "a refused payout still moved funds to bob"
[ "$(bank_aqdn "$contract_addr")" = "$contract_held" ] \
    || fail "the contract's balance changed on a refused payout"
echo "payout refused (qadena code 1159); the $(qdn "$contract_held")qdn stays in the contract"

echo "========================="
echo "WASM TESTS PASSED"
echo "========================="
