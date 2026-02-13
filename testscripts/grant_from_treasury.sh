#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

set -e

# Extract both positional parameters first
pos_args=()
for arg in "$@"; do
    if [[ ! $arg =~ ^-- ]]; then
        pos_args+=("$arg")
    fi
done

# Set variables from positional parameters
if [[ ${#pos_args[@]} -gt 0 ]]; then
    account="${pos_args[1]}"
fi

if [[ ${#pos_args[@]} -gt 1 ]]; then
    amount="${pos_args[2]}"
fi

# Debug info
echo "account or address: $account"
echo "amount: $amount"
# Don't print the mnemonic for security reasons

if [ -z "$account" ] || [ -z "$amount" ]; then
    echo "Usage: $0 <account> <amount>"
    exit 1
fi


echo "-------------------------"
echo "Grant from treasury"
echo "-------------------------"
echo "Sending $amount to $account from treasury"

# check if account is already an address (starts with qadena1) 

if [[ "$account" == qadena1* ]]; then
    qadena_address="$account"
else
    qadena_address=$(qadenad_alias keys show "$account" -a 2>/dev/null)
    if [ -z "$qadena_address" ]; then
        echo "Error: could not resolve key name '$account' to an address"
        exit 1
    fi
fi
echo "Qadena address: $qadena_address"
result=$(qadenad_alias tx bank send treasury $qadena_address  $amount --from treasury --yes --output json --gas-prices $minimum_gas_prices --gas $gas_auto --gas-adjustment $gas_adjustment)
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

