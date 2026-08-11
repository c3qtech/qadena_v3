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
    validator="${pos_args[1]}"
fi

if [[ ${#pos_args[@]} -gt 1 ]]; then
    amount="${pos_args[2]}"
fi

# Debug info
echo "validator: $validator"
echo "amount: $amount"
# Don't print the mnemonic for security reasons

if [ -z "$validator" ] || [ -z "$amount" ]; then
    echo "Usage: $0 <validator> <amount>"
    exit 1
fi


echo "-------------------------"
echo "Staking from treasury"
echo "-------------------------"
echo "Staking $amount to validator $validator from treasury"

# ACCEPTS A KEY NAME **OR** A qadenavaloper... ADDRESS.
#
# The key-name form resolves through the local keyring, which only ever holds this node's own
# pioneer key -- so it cannot name a peer validator at all.  That is fine while one validator holds
# every delegation, and useless the moment the stake is split across the whole validator set (see
# the call site in setup_prerequisites.sh).  The address form is how a peer gets named.
if [[ $validator == qadenavaloper* ]]; then
    qadena_validator_address="$validator"
    echo "Qadena validator address (given directly): $qadena_validator_address"
else
    qadena_address=$(qadenad_alias keys show $validator -a)
    echo "Qadena address: $qadena_address"
    qadena_validator_address=$(qadenad_alias keys show $validator --bech val -a)
    echo "Qadena validator address: $qadena_validator_address"
fi

result=$(qadenad_alias tx staking delegate $qadena_validator_address $amount --from treasury -y --output json --gas-prices $minimum_gas_prices --gas auto --gas-adjustment $gas_adjustment)
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
confirm_tx "$tx_hash" 30 || { echo "tx $tx_hash did not land"; exit 1; }
result=$(qadenad_alias query tx $tx_hash --output json)
echo "Result: $result"
if [ $(echo $result | jq -r .code) -ne 0 ]; then
    echo "ERROR ERROR ERROR"
    echo "Error: $result"
    exit 1
fi

echo "Done"

