. ../funcs.sh

RPC_URL="http://localhost:8545"

MIN_SOLC_VERSION="0.8.29"

# extract the private key
PRIVATE_KEY=$(run_cmd_capture "qadenad keys unsafe-export-eth-key al")

echo "PRIVATE_KEY: $PRIVATE_KEY"

BECH32=$(run_cmd_capture "qadenad keys show al -a")

echo "BECH32: $BECH32"

run_cmd "qadenad debug addr $BECH32"

ETH_ADDR=$(qadenad debug addr $BECH32 2>&1 | grep "Address hex:" | awk '{print $NF}')

echo "ETH_ADDR: $ETH_ADDR"

# show the balance using cast

BALANCE=$(run_cmd_capture "cast balance \"$ETH_ADDR\" --rpc-url \"$RPC_URL\"")

echo "Balance of $ETH_ADDR: $BALANCE"

if ! command -v docker > /dev/null 2>&1; then
    echo "docker could not be found; required to run solc in a container"
    exit 1
fi

if ! docker info > /dev/null 2>&1; then
    echo "docker is installed but the daemon is not reachable (is it running?)"
    echo "try: start Docker Desktop (macOS) or start the docker service (Linux)"
    exit 1
fi

# Compile using solcjs (multi-arch) via node container
rm -rf "solidity/solc_out"
mkdir -p "solidity/solc_out"

soliditydir=`pwd`/solidity
run_cmd "docker run --rm \\
  -v \"$soliditydir:/sources\" \\
  -w /sources \\
  node:20-alpine \\
  sh -lc \"npm -g -s i solc@0.8.29 >/dev/null && solcjs --optimize --abi --bin -o solc_out Store.sol\""

ABI_JSON=$(cat "solidity/solc_out/Store_sol_Store.abi")
BIN_RAW=$(cat "solidity/solc_out/Store_sol_Store.bin")


rm -rf "solidity/solc_out"

jq -n --argjson abi "$ABI_JSON" --arg bin "$BIN_RAW" \
  '{contracts: {"solidity/Store.sol:Store": {abi: $abi, bin: $bin}}}' > "$soliditydir/Store.json"

ABI=$(cat $soliditydir/Store.json | jq -r '.contracts["solidity/Store.sol:Store"].abi')
echo "ABI: $ABI"
export BIN=0x$(cat $soliditydir/Store.json | jq -r '.contracts["solidity/Store.sol:Store"].bin')
echo "BIN: $BIN"

CAST_OUTPUT=$(run_cmd_capture "cast send --rpc-url \"$RPC_URL\" --private-key \"$PRIVATE_KEY\" --create \"$BIN\"")

echo "$CAST_OUTPUT"

TX_HASH=$(echo "$CAST_OUTPUT" | grep "transactionHash" | awk '{print $2}')

echo "Transaction Hash: $TX_HASH"

ADDR=$(run_cmd_capture "cast receipt \"$TX_HASH\" --rpc-url \"$RPC_URL\" | awk '/contractAddress/ {print \$2}'")

echo "Contract Address: $ADDR"

VAL=$(run_cmd_capture "cast call \"$ADDR\" \"value()(uint256)\" --rpc-url \"$RPC_URL\"")
echo "Value: $VAL"

run_cmd "cast send \"$ADDR\" \"set(uint256)\" 42 --rpc-url \"$RPC_URL\" --private-key \"$PRIVATE_KEY\""

VAL=$(run_cmd_capture "cast call \"$ADDR\" \"value()(uint256)\" --rpc-url \"$RPC_URL\"")
echo "New Value: $VAL"

BALANCE=$(run_cmd_capture "cast balance \"$ETH_ADDR\" --rpc-url \"$RPC_URL\"")

echo "Balance of $ETH_ADDR: $BALANCE"


