#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

set -e

# Handle positional and named params separately
unset providername
unset serviceProviderType


# Extract both positional parameters first
pos_args=()
for arg in "$@"; do
    if [[ ! $arg =~ ^-- ]]; then
        pos_args+=("$arg")
    fi
done

# Set variables from positional parameters
if [[ ${#pos_args[@]} -gt 0 ]]; then
    providername="${pos_args[1]}"
fi

if [[ ${#pos_args[@]} -gt 1 ]]; then
    serviceProviderType="${pos_args[2]}"
fi

# Process named options
while [[ $# -gt 0 ]]; do
    case "$1" in
        --pioneer)
            pioneer="$2"
            shift 2
            ;;
        --treasury)
            treasury="$2"
            shift 2
            ;;
        --provider-mnemonic)
            providermnemonic="$2"
            shift 2
            ;;
        --provider-amount)
            provideramount="$2"
            shift 2
            ;;
        --count)
            count="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 <providername> <serviceProviderType> (e.g. identity, finance) [--pioneer <pioneer>] [--treasury <treasury>] [--provider-mnemonic <providermnemonic>] [--provider-amount <provideramount>] [--count <count>]"
            exit 0
            ;;
        --*) # Handle unknown options
            echo "Unknown option: $1"
            shift 1
            ;;
        *) # Skip positional parameters (already handled above)
            shift 1
            ;;
    esac
done

# Debug info
echo "providername: $providername"
echo "serviceProviderType: $serviceProviderType"
echo "pioneer: $pioneer"
echo "treasury: $treasury"
echo "provideramount: $provideramount"
echo "count: $count"
# Don't print the mnemonic for security reasons


if [ -z "$providername" ] || [ -z "$serviceProviderType" ] || [ -z "$pioneer" ] || [ -z "$treasury" ] || [ -z "$provideramount" ] || [ -z "$count" ]; then
    echo "Usage: $0 <providername> <serviceProviderType> (e.g. identity, finance) [--pioneer <pioneer>] [--treasury <treasury>] [--provider-mnemonic <providermnemonic>] [--provider-amount <provideramount>] [--count <count>]"
    exit 1
fi

# compute per-account amount
if [ $count -gt 0 ]; then
    echo "count is greater than 0"
    # Extract numeric prefix (digits)
    numeric_part=${provideramount%%[!0-9]*}

    # Extract suffix (non-digits after the number)
    token_suffix=${provideramount#$numeric_part}

    # Divide
    per_account_amount=$(( numeric_part / (count + 1) ))$token_suffix

    # Output
    echo "per_account_amount: $per_account_amount"
else
    echo "count is 0"
    per_account_amount=$provideramount
fi

echo "-------------------------"
echo "$providername Create wallet"
echo "-------------------------"
qadenad_alias tx qadena create-wallet $providername $pioneer $treasury --account-mnemonic="$providermnemonic"  --yes
qadena_addr=$(qadenad_alias keys show $providername --address)
echo "Sending $provideramount to $qadena_addr from treasury"
result=$(qadenad_alias tx bank send $treasury $qadena_addr  $per_account_amount --from $treasury --yes --output json --gas-prices $minimum_gas_prices --gas auto --gas-adjustment $gas_adjustment)
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

if [ $count -gt 0 ]; then
    for i in $(seq 1 $count); do
        echo "-------------------------"
        echo "$providername Create wallet eph$i"
        echo "-------------------------"
        qadenad_alias tx qadena create-wallet $providername-eph$i $pioneer $treasury --link-to-real-wallet $providername --account-mnemonic="$providermnemonic" --eph-account-index "$i" --yes
        # transfer funds to eph wallet
        qadena_addr=$(qadenad_alias keys show $providername-eph$i --address)
        echo "Sending $per_account_amount to $qadena_addr from treasury $treasury"
        result=$(qadenad_alias tx bank send $treasury $qadena_addr  $per_account_amount --from $treasury --yes --output json --gas-prices $minimum_gas_prices --gas auto --gas-adjustment $gas_adjustment)
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
    done
fi

$qadenaproviderscripts/submit_service_provider_proposal.sh $treasury $providername add_service_provider_proposal $serviceProviderType



