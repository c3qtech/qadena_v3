#!/bin/zsh
#
# Regression test for the EVM: deploy a contract, read and write its storage over JSON-RPC.
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
echo "EVM TESTS PASSED"
echo "========================="
