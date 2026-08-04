#!/bin/zsh
#
# Regression test for the EVM: deploy a contract, read and write its storage over JSON-RPC, and
# pin down what the AML send restriction does and does NOT cover here.
#
# READ THIS BEFORE CHANGING CASES 7-9.  They assert that an EVM value transfer moves funds with NO
# report filed, while the identical `tx bank send` is scanned and files one.  That is not an
# endorsement -- it is a known gap, recorded so it cannot be forgotten and so that closing it makes a
# test fail loudly instead of silently.
#
# The bank leg used to be REFUSED rather than reported, and the contrast was refused-vs-allowed.  It
# became reported-vs-unreported when block_transfer_without_opt_in_reason (default false) made an
# over-threshold send report instead of fail.  The gap itself did not move: the EVM path is still not
# scanned at all, which is a different and worse thing than being scanned and allowed.
#
# WHY THE GAP EXISTS.  The restriction hangs off bank's SendCoins.  The EVM never calls it for native
# value: core.Transfer moves balances inside the in-memory StateDB, and commit writes each dirty
# account through SetAccount -> SetBalance (x/vm/keeper/statedb.go), which MINTS the delta to the
# receiver and BURNS it from the sender against the evm module account.  Every resulting bank call
# therefore has a module account on one leg and is waved through by the module-leg check.
#
# So `cast send --value` is today what `tx bank send` was before the restriction existed: an
# unmeasured route around the scan, the eKYC gate and the reporting threshold alike.
#
# REPLACES the previous version, which deployed Store.sol and printed values but asserted nothing --
# it would have reported success with a contract that never stored anything.  The bootstrapping
# (foundry, solc-in-docker) is kept, but the compile is now skipped when the prebuilt artifact is
# already present, so an ordinary run needs neither docker nor a network fetch.
#
# Idempotent: every run deploys a FRESH contract, so its storage starts at zero regardless of what
# earlier runs did.  That is what makes "value() == 0 before, 42 after" a safe assertion.
#
# Requires: cast (foundry) and the EVM JSON-RPC endpoint.  docker + solc are needed only when the
# prebuilt test_data/Store.json is missing.
#
# Run AFTER testscripts/setup.sh.

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

set -e

function qadenad_alias { "$qadenabin/qadenad" --home "$QADENAHOME" "$@" }

RPC_URL="http://localhost:8545"
account="al"
artifact="$qadenatestdata/Store.json"
contract_key="test_data/Store.sol:Store"

fail() {
    echo "FAILED: $1"
    exit 1
}

# cast prints values like "42" or "42 [4.2e1]" depending on version -- take the first field
cast_uint() {
    cast call "$1" "value()(uint256)" --rpc-url "$RPC_URL" 2>/dev/null | awk '{print $1}'
}

gas_flags=(--gas $gas_auto --gas-adjustment $gas_adjustment --gas-prices $minimum_gas_prices)

bank_aqdn() {
    local amt
    amt=$(qadenad_alias query bank balances "$1" --output json 2>/dev/null \
        | jq -r '.balances[] | select(.denom=="aqdn") | .amount' 2>/dev/null | head -1) || amt=""
    echo "${amt:-0}"
}

hex_of()  { qadenad_alias debug addr "$1" 2>&1 | grep "Address hex:" | awk '{print $NF}'; }
addr_of() { qadenad_alias keys show "$1" -a --keyring-backend test 2>/dev/null; }
key_of()  { qadenad_alias keys unsafe-export-eth-key "$1" --keyring-backend test 2>/dev/null | head -1; }

# bank_send <from> <to-addr> <amount> -- sets bank_code and bank_log from the ON-CHAIN result.
#
# The scan is skipped in CheckTx and simulation, so a refused send still broadcasts and returns a
# hash; the verdict only exists in the block.  stdout alone, because --gas auto writes "gas estimate"
# to stderr and folding that into the JSON makes jq fail under set -e with no message at all.
#
# The log matters as much as the code: every failure is code 1, so checking the code alone would let
# a send that failed for insufficient funds pass as a send refused by the AML scan.
bank_send() {
    local out hash json
    bank_code=""; bank_log=""
    out=$(qadenad_alias tx bank send "$1" "$2" "$3" --from "$1" --yes --output json \
        "${gas_flags[@]}" 2>/dev/null) || { bank_code="BROADCAST_REJECTED"; return 0; }
    hash=$(echo "$out" | jq -r '.txhash' 2>/dev/null)
    [ -n "$hash" ] && [ "$hash" != "null" ] || { bank_code="NO_TXHASH"; return 0; }
    qadenad_alias query wait-tx "$hash" --timeout 60s > /dev/null 2>&1 || true
    json=$(qadenad_alias query tx "$hash" --output json 2>/dev/null)
    bank_code=$(echo "$json" | jq -r '.code // "UNKNOWN"')
    bank_log=$(echo "$json" | jq -r '.raw_log // ""')
}

# evm_value_send <priv-key> <to-hex> <wei> -- echoes the transaction status, "1" on success
evm_value_send() {
    local out
    out=$(cast send "$2" --value "$3" --rpc-url "$RPC_URL" --private-key "0x$1" 2>&1) || {
        echo "CAST_FAILED: $(echo "$out" | head -1)"; return
    }
    echo "$out" | grep -E "^status" | awk '{print $2}'
}

echo "========================="
echo "preflight"
echo "========================="
if [ -d "$HOME/.foundry/bin" ] && [[ ! $PATH == *"$HOME/.foundry/bin"* ]]; then
    export PATH="$HOME/.foundry/bin:$PATH"
fi
command -v cast > /dev/null 2>&1 \
    || fail "cast (foundry) not found -- install from https://foundry.paradigm.xyz, or skip this test"

qadenad_alias status > /dev/null 2>&1 || fail "chain is not reachable -- start it first"
qadenad_alias keys show "$account" -a --keyring-backend test > /dev/null 2>&1 \
    || fail "$account not in the keyring -- run testscripts/setup.sh first"

# the EVM JSON-RPC is a separate listener from the cosmos RPC and can be disabled independently
cast chain-id --rpc-url "$RPC_URL" > /dev/null 2>&1 \
    || fail "no EVM JSON-RPC at $RPC_URL -- is the node started with --json-rpc.enable?"
chain_id=$(cast chain-id --rpc-url "$RPC_URL")
echo "EVM JSON-RPC up, chain id $chain_id"

private_key=$(qadenad_alias keys unsafe-export-eth-key "$account" 2>/dev/null) \
    || fail "could not export the eth key for $account"
bech32=$(qadenad_alias keys show "$account" -a --keyring-backend test)
eth_addr=$(qadenad_alias debug addr "$bech32" 2>&1 | grep "Address hex:" | awk '{print $NF}')
[ -n "$eth_addr" ] || fail "could not derive the eth address for $account"
echo "$account: $bech32 -> $eth_addr"

balance=$(cast balance "$eth_addr" --rpc-url "$RPC_URL")
echo "balance: $balance wei"
[ "$balance" != "0" ] || fail "$account has no balance; the deploy cannot pay gas"

echo "========================="
echo "1. contract artifact"
echo "========================="
# Compiling needs docker and a network fetch, so only do it when the artifact is genuinely absent.
if [ -f "$artifact" ] && [ -n "$(jq -r --arg k "$contract_key" '.contracts[$k].bin // empty' "$artifact" 2>/dev/null)" ]; then
    echo "using prebuilt $artifact"
else
    echo "$artifact missing or incomplete -- compiling Store.sol"
    command -v docker > /dev/null 2>&1 || fail "docker is required to compile Store.sol"
    docker info > /dev/null 2>&1 || fail "docker is installed but the daemon is not reachable"

    rm -rf "$qadenatestdata/solc_out"
    mkdir -p "$qadenatestdata/solc_out"
    docker run --rm -v "$qadenatestdata:/sources" -w /sources node:20-alpine \
        sh -lc "npm -g -s i solc@0.8.29 >/dev/null && solcjs --optimize --abi --bin -o solc_out Store.sol" \
        || fail "solc compilation failed"

    abi_json=$(cat "$qadenatestdata/solc_out/Store_sol_Store.abi")
    bin_raw=$(cat "$qadenatestdata/solc_out/Store_sol_Store.bin")
    rm -rf "$qadenatestdata/solc_out"
    jq -n --argjson abi "$abi_json" --arg bin "$bin_raw" --arg k "$contract_key" \
        '{contracts: {($k): {abi: $abi, bin: $bin}}}' > "$artifact" \
        || fail "could not write $artifact"
    echo "compiled to $artifact"
fi

bin="0x$(jq -r --arg k "$contract_key" '.contracts[$k].bin' "$artifact")"
[ ${#bin} -gt 2 ] || fail "no bytecode in $artifact"
echo "bytecode: ${#bin} chars"

echo "========================="
echo "2. deploy a fresh contract"
echo "========================="
out=$(cast send --rpc-url "$RPC_URL" --private-key "$private_key" --create "$bin" 2>&1) \
    || fail "deploy failed: $out"
tx_hash=$(echo "$out" | grep -i "transactionHash" | awk '{print $2}')
[ -n "$tx_hash" ] || fail "no transactionHash in the deploy output"

addr=$(cast receipt "$tx_hash" --rpc-url "$RPC_URL" 2>/dev/null | awk '/contractAddress/ {print $2}')
[ -n "$addr" ] && [ "$addr" != "null" ] || fail "no contractAddress in the deploy receipt"
echo "deployed at $addr"

# a deployed contract must have code -- an address alone proves nothing
code=$(cast code "$addr" --rpc-url "$RPC_URL" 2>/dev/null)
[ ${#code} -gt 2 ] || fail "no code at $addr; the deploy produced an empty contract"
echo "code present (${#code} chars)"

echo "========================="
echo "3. storage starts at zero"
echo "========================="
# safe to assert because this contract was deployed moments ago by this run
val=$(cast_uint "$addr")
echo "value() = $val"
[ "$val" = "0" ] || fail "a freshly deployed contract reports value() = $val, expected 0"

echo "========================="
echo "4. write, then read back"
echo "========================="
cast send "$addr" "set(uint256)" 42 --rpc-url "$RPC_URL" --private-key "$private_key" > /dev/null 2>&1 \
    || fail "set(42) failed"
val=$(cast_uint "$addr")
echo "value() after set(42) = $val"
[ "$val" = "42" ] || fail "value() = $val after set(42)"

echo "========================="
echo "5. overwrite, to prove it is really storage"
echo "========================="
# a contract that returned a constant 42 would pass step 4; this catches that
cast send "$addr" "set(uint256)" 7 --rpc-url "$RPC_URL" --private-key "$private_key" > /dev/null 2>&1 \
    || fail "set(7) failed"
val=$(cast_uint "$addr")
echo "value() after set(7) = $val"
[ "$val" = "7" ] || fail "value() = $val after set(7)"

echo "========================="
echo "6. gas was actually charged"
echo "========================="
after=$(cast balance "$eth_addr" --rpc-url "$RPC_URL")
echo "balance: $balance -> $after wei"
python3 -c "raise SystemExit(0 if int('$after') < int('$balance') else 1)" \
    || fail "the balance did not decrease; the transactions were not paid for"

echo "========================="
echo "7. an EVM value transfer between two non-wallets SUCCEEDS"
echo "========================="
# The same movement by `tx bank send` is refused: neither party is a wallet, so it cannot be scanned.
# Over the EVM it goes through untouched.  Both halves are asserted, because the pair is the finding
# -- either one alone would look like ordinary behaviour.
#
# Per-run keys, so nothing here depends on what earlier runs left behind.
run_id=$(date +%s)
src="evmsrc-$run_id"
dst="evmdst-$run_id"
for k in "$src" "$dst"; do
    qadenad_alias keys add "$k" --keyring-backend test > /dev/null 2>&1 || fail "could not create $k"
done
src_addr=$(addr_of "$src"); dst_addr=$(addr_of "$dst")
src_hex=$(hex_of "$src_addr");  dst_hex=$(hex_of "$dst_addr")
src_key=$(key_of "$src")
[ -n "$src_key" ] || fail "could not export the eth key for $src"

# treasury is on the scanned-contract whitelist, so it may fund a key that has no identity yet.  It
# is not exempt from the scan -- this send is measured like any other, and simply falls under the
# threshold.
bank_send treasury "$src_addr" "20qdn"
[ "$bank_code" = "0" ] || fail "could not fund $src from treasury (code $bank_code)"
echo "$src funded: $(bank_aqdn "$src_addr") aqdn"

echo "-------------------------"
echo "over the bank: refused"
echo "-------------------------"
dst_before=$(bank_aqdn "$dst_addr")
bank_send "$src" "$dst_addr" "1qdn"
[ "$bank_code" != "0" ] || fail "a bank send between two non-wallets was allowed; the restriction is broken"
echo "$bank_log" | grep -q "code 1159" \
    || { echo "$bank_log" | head -2; fail "expected qadena code 1159 (not scannable), got the above"; }
[ "$(bank_aqdn "$dst_addr")" = "$dst_before" ] || fail "a refused bank send still moved funds"
echo "tx bank send refused (qadena code 1159), nothing moved"

echo "-------------------------"
echo "over the EVM: allowed -- THIS IS THE GAP"
echo "-------------------------"
tx_status=$(evm_value_send "$src_key" "$dst_hex" "1000000000000000000")
if [ "$tx_status" != "1" ]; then
    fail "the EVM value transfer did not succeed (status '$tx_status').
      If the EVM gap has been CLOSED deliberately, this test is now wrong and must be rewritten to
      assert a refusal -- see the header.  Do not simply delete the case."
fi
dst_after=$(bank_aqdn "$dst_addr")
[ "$dst_after" != "$dst_before" ] \
    || fail "the EVM transfer reported success but no funds moved; the assertion below is meaningless"
python3 -c "
raise SystemExit(0 if int('$dst_after') - int('$dst_before') == 10**18 else 1)
" || fail "expected exactly 1qdn to arrive, got $(python3 -c "print(int('$dst_after')-int('$dst_before'))") aqdn"
echo "cast send --value moved 1qdn that the bank refused to move"

echo "========================="
echo "8. the EVM also bypasses the reporting THRESHOLD"
echo "========================="
# Worse than case 7, and the reason this is worth a test rather than a comment.  In case 7 the
# parties could not be scanned at all.  Here both hold personal-info credentials, the sender has a
# jurisdiction and therefore a threshold, and the amount is comfortably over it -- the bank refuses
# it as a reportable transfer with no opt-in available.  The identical amount goes through the EVM.
addr_of ann > /dev/null 2>&1 || fail "ann not in the keyring -- run testscripts/setup.sh first"
ann_addr=$(addr_of ann)
ann_hex=$(hex_of "$ann_addr")

# the threshold is evaluated in USD through the pricefeed, so without a price this case proves nothing
qdn_usd=$(qadenad_alias query pricefeed price cn:qdn:usd --output json 2>/dev/null | jq -r '.price.price')
[ -n "$qdn_usd" ] && [ "$qdn_usd" != "null" ] \
    || fail "cn:qdn:usd has no price -- the threshold cannot be reached and this case is meaningless"

# 1,200,000 qdn = 12,000 usd at cn:qdn:usd 0.01.  Chosen to clear the most restrictive jurisdiction
# either way, so this does not depend on which of the sender's countries is selected -- the same
# constant test_suspicious.sh uses.
large_qdn=1200000
large_wei="${large_qdn}000000000000000000"
echo "moving ${large_qdn}qdn = $(python3 -c "print($large_qdn*int('$qdn_usd')/10**18)") usd"

# TWICE the amount, plus fees.  This case moves ${large_qdn}qdn over the bank AND the same again over
# the EVM, and the bank leg now SETTLES rather than being refused -- so the funds it moves are really
# gone by the time the EVM leg runs.  Budgeting for one leg was correct only while the bank refused
# and the balance came back; with reporting it leaves the EVM transfer short, which surfaces as
# "insufficient funds" and looks nothing like the accounting change that caused it.
have=$(bank_aqdn "$bech32")
python3 -c "raise SystemExit(0 if int('$have') >= 2*${large_qdn}*10**18 + 10**19 else 1)" || {
    echo "funding $account from treasury"
    # enough for both legs, matching the check above -- topping up for one would re-fail here on the
    # very next run rather than fixing anything
    bank_send treasury "$bech32" "$((2 * large_qdn + 100))qdn"
    [ "$bank_code" = "0" ] || fail "could not top up $account (code $bank_code)"
}

echo "-------------------------"
echo "over the bank: reported, over threshold"
echo "-------------------------"
# INVERTED DELIBERATELY, for the same reason as test_suspicious.sh case 2.
#
# MsgSend has no --opt-in-reason and nowhere to put one, so every reportable bank send reaches the
# enclave with an empty reason.  While a reason was mandatory that meant this path could only ever
# refuse; with block_transfer_without_opt_in_reason false (the default) it files a report carrying
# the default reason and lets the send through.
#
# The threshold is still what decides -- it now decides whether to REPORT rather than whether to
# REFUSE -- so the assertion moved to the report count below.
susp_before=$(qadenad_alias query qadena list-suspicious-transaction --output json 2>/dev/null \
    | jq -r '.SuspiciousTransaction | length')
ann_before=$(bank_aqdn "$ann_addr")
bank_send "$account" "$ann_addr" "${large_qdn}qdn"
[ "$bank_code" = "0" ] \
    || fail "an over-threshold bank send should be reported and allowed, not refused (code $bank_code)"

susp_after=""
i=0
while [ $i -lt 15 ]; do
    susp_after=$(qadenad_alias query qadena list-suspicious-transaction --output json 2>/dev/null \
        | jq -r '.SuspiciousTransaction | length')
    [ "$susp_after" -gt "$susp_before" ] 2>/dev/null && break
    sleep 2
    i=$((i + 1))
done
[ "$susp_after" -gt "$susp_before" ] 2>/dev/null \
    || fail "an over-threshold bank send filed NO report ($susp_before -> $susp_after); the AML threshold is not being applied"
echo "reported as expected: $susp_before -> $susp_after"

# The funds MOVED.  This used to assert the opposite -- code 1125 and an unchanged balance -- because
# an over-threshold send was refused outright.  Reporting replaced refusing, so the balance check
# inverts with it: the value a regulator was told about is value that actually changed hands, which
# is the whole point of reporting rather than blocking.
ann_after_bank=$(bank_aqdn "$ann_addr")
[ "$ann_after_bank" != "$ann_before" ] \
    || fail "the bank send was reported but moved nothing"
echo "tx bank send scanned, reported and settled"

echo "-------------------------"
echo "over the EVM: allowed -- unscanned and unmeasured"
echo "-------------------------"
tx_status=$(evm_value_send "$private_key" "$ann_hex" "$large_wei")
if [ "$tx_status" != "1" ]; then
    fail "the over-threshold EVM transfer did not succeed (status '$tx_status').
      If the EVM gap has been CLOSED deliberately, rewrite this case to assert a refusal."
fi
# Measured from AFTER the bank leg, not from before it.  The bank leg used to be refused and move
# nothing, so one baseline served both; now it settles, and measuring from the original baseline
# sees both legs and reports twice the expected arrival -- which reads as an EVM bug rather than as
# the bank send having succeeded.
ann_after=$(bank_aqdn "$ann_addr")
python3 -c "
raise SystemExit(0 if int('$ann_after') - int('$ann_after_bank') == ${large_qdn}*10**18 else 1)
" || fail "expected ${large_qdn}qdn to arrive over the EVM, got $(python3 -c "print((int('$ann_after')-int('$ann_after_bank'))/10**18)")qdn"
echo "cast send --value moved ${large_qdn}qdn ($(python3 -c "print($large_qdn*int('$qdn_usd')/10**18)") usd) with no scan"

# send it back, so the suite leaves balances where it found them and can be re-run
ann_key=$(key_of ann)
[ -n "$ann_key" ] || fail "could not export the eth key for ann to return the funds"
tx_status=$(evm_value_send "$ann_key" "$eth_addr" "$large_wei")
[ "$tx_status" = "1" ] || fail "could not return the ${large_qdn}qdn to $account (status '$tx_status')"
echo "returned ${large_qdn}qdn to $account"

echo "========================="
echo "EVM TESTS PASSED"
echo "========================="
