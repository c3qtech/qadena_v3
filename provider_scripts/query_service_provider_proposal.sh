#!/bin/zsh

# Extract both positional parameters first
pos_args=()
for arg in "$@"; do
    if [[ ! $arg =~ ^-- ]]; then
        pos_args+=("$arg")
    fi
done

# Set variables from positional parameters
if [[ ${#pos_args[@]} -gt 0 ]]; then
    proposal_id="${pos_args[1]}"
fi

wait=false
proposal_status="PROPOSAL_STATUS_PASSED"

# Process named options
while [[ $# -gt 0 ]]; do
    case "$1" in
        --wait)
            wait=true
            shift 1
            ;;
        --status)
            proposal_status="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 <proposal_id> [--wait] [--status <status>]"
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

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

if [ -z $proposal_id ] ; then
    echo "Usage: ./query_service_provider_proposal.sh <proposal_id>"
    exit 1
fi

# wait until proposal is passed
while true; do
    stat=$(qadenad_alias query gov proposal $proposal_id --output json | jq -r '.proposal.status')
    if [ "$stat" = "$proposal_status" ]; then
        echo "Proposal $proposal_id is $stat"
        break
    fi
    if [ "$wait" = true ]; then
        echo "Waiting for proposal $proposal_id to reach status $proposal_status..."
        echo "Date: $(date -z UTC)"
        echo "Proposal: $(qadenad_alias query gov proposal $proposal_id --output json)"
        echo "Votes: $(qadenad_alias query gov votes $proposal_id --output json)"
        echo "Deposits: $(qadenad_alias query gov deposits $proposal_id --output json)"
        sleep 3
    else
        echo "Proposal $proposal_id is not $proposal_status (status: $stat)"
        exit 1
    fi
done
