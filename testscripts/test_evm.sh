#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

RPC_URL="http://localhost:8545"

# check if "al" already exists

if qadenad_alias keys show al > /dev/null 2>&1; then
    echo "al already exists"
else
    $qadenatestscripts/setup.sh --specific-user al
fi


# extract the private key
PRIVATE_KEY=$(qadenad_alias keys unsafe-export-eth-key al)

echo "PRIVATE_KEY: $PRIVATE_KEY"

BECH32=$(qadenad_alias keys show al -a)

echo "BECH32: $BECH32"

ETH_ADDR=$(qadenad_alias debug addr $BECH32 2>&1 | grep "Address hex:" | awk '{print $NF}')

echo "ETH_ADDR: $ETH_ADDR"

# show the balance using cast

BALANCE=$(cast balance $ETH_ADDR --rpc-url $RPC_URL)

echo "Balance of $ETH_ADDR: $BALANCE"

solc --optimize --combined-json abi,bin $qadenatestdata/Store.sol > $qadenatestdata/Store.json 

ABI=$(cat $qadenatestdata/Store.json | jq -r '.contracts["test_data/Store.sol:Store"].abi')
echo "ABI: $ABI"
export BIN=0x$(cat $qadenatestdata/Store.json | jq -r '.contracts["test_data/Store.sol:Store"].bin')
echo "BIN: $BIN"

CAST_OUTPUT=$(cast send  \
  --rpc-url "$RPC_URL" \
  --private-key "$PRIVATE_KEY" \
  --create "$BIN")

echo "$CAST_OUTPUT"

TX_HASH=$(echo "$CAST_OUTPUT" | grep "transactionHash" | awk '{print $2}')

echo "Transaction Hash: $TX_HASH"

ADDR=$(cast receipt "$TX_HASH" --rpc-url "$RPC_URL" | awk '/contractAddress/ {print $2}')

echo "Contract Address: $ADDR"

VAL=$(cast call "$ADDR" "value()(uint256)" --rpc-url "$RPC_URL")
echo "Value: $VAL"

cast send "$ADDR" "set(uint256)" 42 --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY"

VAL=$(cast call "$ADDR" "value()(uint256)" --rpc-url "$RPC_URL")
echo "New Value: $VAL"

BALANCE=$(cast balance $ETH_ADDR --rpc-url $RPC_URL)

echo "Balance of $ETH_ADDR: $BALANCE"
