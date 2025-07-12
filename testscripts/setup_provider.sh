#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

set -e

pioneer="pioneer1"
createwalletsponsor="sec-create-wallet-sponsor"
providermnemonic=$(qadenad_alias keys mnemonic)
count="2"

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
        --create-wallet-sponsor)
            createwalletsponsor="$2"
            shift 2
            ;;
        --provider-mnemonic)
            providermnemonic="$2"
            shift 2
            ;;
        --count)
            count="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 <providername> <serviceProviderType> [--pioneer <pioneer>] [--create-wallet-sponsor <createwalletsponsor>] [--provider-mnemonic <providermnemonic>] [--count <count>]"
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
echo "createwalletsponsor: $createwalletsponsor"
echo "count: $count"
# Don't print the mnemonic for security reasons

if [ -z "$providername" ] || [ -z "$serviceProviderType" ]; then
    echo "Usage: $0 <providername> <serviceProviderType>"
    exit 1
fi


echo "-------------------------"
echo "$providername Create wallet"
echo "-------------------------"
qadenad_alias tx qadena create-wallet $providername $pioneer $createwalletsponsor --account-mnemonic="$providermnemonic"  --yes

for i in $(seq 1 $count); do
    echo "-------------------------"
    echo "$providername Create wallet eph$i"
    echo "-------------------------"
    qadenad_alias tx qadena create-wallet $providername-eph$i $pioneer $createwalletsponsor --link-to-real-wallet $providername --account-mnemonic="$providermnemonic" --eph-account-index "$i" --yes
    # transfer funds to eph wallet
    qadena_addr=$(qadenad_alias keys show $providername-eph$i --address)
    result=$(qadenad_alias tx bank send treasury $qadena_addr  10000000000qdn --from treasury --yes --output json)
    # get tx hash
    tx_hash=$(echo $result | jq -r .txhash)
    echo "tx hash: $tx_hash"
    # wait for result
    qadenad_alias query wait-tx $tx_hash
done

$qadenatestscripts/test_submit_service_provider_proposal.sh $providername add_service_provider_proposal $serviceProviderType



