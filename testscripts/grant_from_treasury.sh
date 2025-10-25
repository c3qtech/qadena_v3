#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

set -e

pioneer="pioneer1"

# Extract both positional parameters first
pos_args=()
for arg in "$@"; do
    if [[ ! $arg =~ ^-- ]]; then
        pos_args+=("$arg")
    fi
done

# Set variables from positional parameters
if [[ ${#pos_args[@]} -gt 0 ]]; then
    name="${pos_args[1]}"
fi

if [[ ${#pos_args[@]} -gt 1 ]]; then
    amount="${pos_args[2]}"
fi

# Debug info
echo "name: $name"
echo "amount: $amount"
# Don't print the mnemonic for security reasons

if [ -z "$name" ] || [ -z "$amount" ]; then
    echo "Usage: $0 <name> <amount>"
    exit 1
fi


echo "-------------------------"
echo "Grant from treasury"
echo "-------------------------"
qadena_addr=$(qadenad_alias keys show $name --address)
echo "Sending $amount to $qadena_addr from treasury"
result=$(qadenad_alias tx bank send treasury $qadena_addr  $amount --from treasury --yes --output json --gas-prices $minimum_gas_prices --gas $gas_auto --gas-adjustment $gas_adjustment)
echo "Result: $result"
# get tx hash
tx_hash=$(echo $result | jq -r .txhash)
echo "tx hash: $tx_hash"
# check if code is 0
if [ $(echo $result | jq -r .code) -ne 0 ]; then
    echo "Error: $(echo $result | jq -r .message)"
    exit 1
fi
# wait for result
qadenad_alias query wait-tx $tx_hash --timeout 30s

echo "Done"

