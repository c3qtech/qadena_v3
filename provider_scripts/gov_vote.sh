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
    treasury="${pos_args[1]}"
fi

if [[ ${#pos_args[@]} -gt 1 ]]; then
    proposal_id="${pos_args[2]}"
fi

if [[ ${#pos_args[@]} -gt 2 ]]; then
    vote="${pos_args[3]}"
fi

# Debug info
echo "treasury: $treasury"
echo "proposal_id: $proposal_id"
echo "vote: $vote"
# Don't print the mnemonic for security reasons

if [ -z "$treasury" ] || [ -z "$proposal_id" ] || [ -z "$vote" ]; then
    echo "Usage: $0 <treasury> <proposal_id> <vote>"
    exit 1
fi


echo "-------------------------"
echo "Vote from treasury"
echo "-------------------------"
echo "Voting $vote on proposal $proposal_id from $treasury"
# increase gas_adjustment to 2
echo "Original gas adjustment: $gas_adjustment"
export gas_adjustment=2
echo "New gas adjustment: $gas_adjustment"
result=$(qadenad_alias tx gov vote $proposal_id $vote --from $treasury -y --output json --gas-prices $minimum_gas_prices --gas auto --gas-adjustment $gas_adjustment)
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
result=$(qadenad_alias query wait-tx $tx_hash --output json --timeout 30s)
echo "Result: $result"
if [ $(echo $result | jq -r .code) -ne 0 ]; then
    echo "ERROR ERROR ERROR"
    echo "Error: $result"
    exit 1
fi

# get vote status
votes=$(qadenad_alias query gov votes $proposal_id --output json)
echo "Votes: $votes"

# get proposal status
proposal=$(qadenad_alias query gov proposal $proposal_id --output json)
echo "Proposal: $proposal"

echo "Done"

