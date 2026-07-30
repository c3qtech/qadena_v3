#!/bin/zsh
#
# Regression test for CosmWasm: store -> instantiate -> execute.
#
# REPLACES the previous version, which was a demo with no assertions and was not re-runnable -- it
# began with `keys add alice`, which fails once alice exists.  This version asserts and is
# idempotent.
#
# Uses test_data/hackatom.wasm: the contract holds funds and releases them to a beneficiary when the
# verifier executes {"release":{}}.  That makes it a genuine end-to-end check, because success is
# visible as moved balance rather than only a tx receipt.
#
# Execution goes through `tx qadena execute-wasm`, the Qadena wrapper, rather than plain
# `tx wasm execute` -- that is the path this chain actually uses and therefore the one worth
# regression-testing.
#
# Idempotent: accounts are created only if missing and topped up only if empty, and each run stores
# and instantiates its own contract instance under a per-run label.
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

fail() {
    echo "FAILED: $1"
    exit 1
}

bank_aqdn() {
    local amt
    amt=$(qadenad_alias query bank balances "$1" --output json 2>/dev/null \
        | jq -r '.balances[] | select(.denom=="aqdn") | .amount' 2>/dev/null) || amt=""
    echo "${amt:-0}"
}

qdn() { python3 -c "print(int('${1:-0}')/10**18)"; }

# create the account if missing, fund it if empty -- guarded separately so a run that died between
# the two does not leave an unfunded key that the next run skips over
ensure_account() {
    local name="$1" addr result tx_hash
    if ! qadenad_alias keys show "$name" --keyring-backend test > /dev/null 2>&1; then
        qadenad_alias keys add "$name" --keyring-backend test > /dev/null 2>&1 \
            || fail "could not create $name"
    fi
    addr=$(qadenad_alias keys show "$name" -a --keyring-backend test)
    if [ "$(bank_aqdn "$addr")" = "0" ]; then
        result=$(qadenad_alias tx bank send "$funder" "$addr" "$account_funding" \
            --from "$funder" --yes --output json \
            --gas-prices $minimum_gas_prices --gas $gas_auto --gas-adjustment $gas_adjustment) \
            || fail "could not fund $name"
        tx_hash=$(echo "$result" | jq -r .txhash)
        qadenad_alias query wait-tx "$tx_hash" --timeout 30s > /dev/null \
            || fail "funding $name did not land"
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
result=$(qadenad_alias tx wasm store "$wasm_file" --from alice --yes --output json \
    --gas-prices $minimum_gas_prices --gas $gas_auto --gas-adjustment $gas_adjustment) \
    || fail "tx wasm store failed"
tx_hash=$(echo "$result" | jq -r .txhash)
qadenad_alias query wait-tx "$tx_hash" --timeout 60s > /dev/null || fail "store tx did not land"

code_id=$(qadenad_alias query tx "$tx_hash" --output json 2>/dev/null \
    | jq -r '.events[] | select(.type=="store_code").attributes[] | select(.key=="code_id").value' | head -1)
[ -n "$code_id" ] || fail "no code_id in the store tx events"
echo "code id: $code_id"

echo "========================="
echo "2. instantiate it holding $send_amount"
echo "========================="
init="{\"verifier\":\"$alice_addr\",\"beneficiary\":\"$bob_addr\"}"
result=$(qadenad_alias tx wasm instantiate "$code_id" "$init" \
    --admin "$alice_addr" --label "$label" --amount "$send_amount" \
    --from alice --yes --output json \
    --gas-prices $minimum_gas_prices --gas $gas_auto --gas-adjustment $gas_adjustment) \
    || fail "tx wasm instantiate failed"
tx_hash=$(echo "$result" | jq -r .txhash)
qadenad_alias query wait-tx "$tx_hash" --timeout 60s > /dev/null || fail "instantiate tx did not land"

contract_addr=$(qadenad_alias query wasm list-contract-by-code "$code_id" --output json 2>/dev/null \
    | jq -r '.contracts[-1]')
[ -n "$contract_addr" ] && [ "$contract_addr" != "null" ] \
    || fail "no contract address for code id $code_id"
echo "contract: $contract_addr"

echo "-------------------------"
echo "the contract must actually hold what it was instantiated with"
echo "-------------------------"
contract_before=$(bank_aqdn "$contract_addr")
[ "$contract_before" != "0" ] \
    || fail "the contract holds nothing after being instantiated with $send_amount"
echo "contract holds $(qdn "$contract_before")qdn"

qadenad_alias query wasm contract "$contract_addr" --output json > /dev/null 2>&1 \
    || fail "the instantiated contract is not queryable"
echo "contract queryable"

echo "========================="
echo "3. execute {\"release\":{}} through qadena execute-wasm"
echo "========================="
bob_before=$(bank_aqdn "$bob_addr")
echo "bob before: $(qdn "$bob_before")qdn"

# No JSON parsing here: the qadena CLI interleaves progress output with the response on stdout, so
# jq cannot read it.  It also broadcasts synchronously (GenerateOrBroadcastTxCLISync) and returns
# non-zero when the message fails, so the exit code is the verdict and no wait-tx is needed.
qadenad_alias tx qadena execute-wasm "$contract_addr" '{"release":{}}' \
    --from alice --yes \
    --gas-prices $minimum_gas_prices --gas $gas_auto --gas-adjustment $gas_adjustment > /dev/null 2>&1 \
    || fail "tx qadena execute-wasm failed"
echo "executed"

# balances settle a block later
for _ in {1..15}; do
    [ "$(bank_aqdn "$contract_addr")" = "0" ] && break
    sleep 2
done

echo "========================="
echo "4. the release moved real funds"
echo "========================="
# a receipt only says the message ran; the balances say it did something
bob_after=$(bank_aqdn "$bob_addr")
contract_after=$(bank_aqdn "$contract_addr")
echo "bob after:  $(qdn "$bob_after")qdn"
echo "contract:   $(qdn "$contract_before")qdn -> $(qdn "$contract_after")qdn"

python3 -c "raise SystemExit(0 if int('$bob_after') > int('$bob_before') else 1)" \
    || fail "bob's balance did not increase after release"
[ "$contract_after" = "0" ] \
    || fail "the contract still holds $(qdn "$contract_after")qdn after release"

# and the amounts must agree -- the contract's whole balance went to bob
python3 -c "
raise SystemExit(0 if int('$bob_after') - int('$bob_before') == int('$contract_before') else 1)
" || fail "bob gained $(qdn $(python3 -c "print(int('$bob_after')-int('$bob_before'))")) but the contract held $(qdn "$contract_before")"
echo "the contract's full balance reached bob"

echo "========================="
echo "WASM TESTS PASSED"
echo "========================="
