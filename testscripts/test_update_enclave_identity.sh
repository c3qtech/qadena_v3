#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

uniqueid=$1
signerid=$2
stat=$3

if [ -z $uniqueid ] || [ -z $signerid ] || [ -z $stat ] ; then
    echo "Usage: ./test_update_enclave_identity.sh <uniqueid> <signerid> <status>"
    exit 1
fi

# stat must be "inactive" or "unvalidated"
if [ $stat != "inactive" ] && [ $stat != "unvalidated" ] ; then
    echo "status must be \"inactive\" or \"unvalidated\""
    exit 1
fi

cd $qadenabuild

json_proposal="update_enclave_identity"

# modify json_proposal
# Modify json_proposal
jq --arg uniqueid "$uniqueid" \
   --arg signerid "$signerid" \
   --arg status "$stat" \
   '.messages[0] |= (.uniqueID = $uniqueid | .signerID = $signerid | .status = $status)' \
   "test_data/$json_proposal.json" > "test_data/$json_proposal.gen.json"


# submit json_proposal
submit_hash=$(qadenad_alias tx gov submit-proposal "test_data/$json_proposal.gen.json" --from pioneer1 -y --output json --gas-prices $minimum_gas_prices --gas $gas_auto --gas-adjustment $gas_adjustment | jq -r '.txhash')
echo $submit_hash

# wait for the proposal to be submitted
#
# confirm_tx, not a bare wait-tx: that subscribes to an event and reports failure for a transaction
# already included before the subscription existed.  This runs right after a chain restart in the
# enclave upgrade suite, which is exactly when that happens.
confirm_tx "$submit_hash" 30 || { echo "proposal submission $submit_hash did not land"; exit 1; }

# Get the proposal ID
proposal_id=$(qadenad_alias query tx $submit_hash --output json | jq -r '.events[] | select(.type=="submit_proposal") | .attributes[] | select(.key=="proposal_id") | .value')
echo $proposal_id

# deposit into the proposal
deposit_hash=$(qadenad_alias tx gov deposit $proposal_id 1000qdn --from pioneer1 -y --output json --gas-prices $minimum_gas_prices --gas $gas_auto --gas-adjustment $gas_adjustment | jq -r '.txhash')
echo $deposit_hash

# wait for the deposit to be submitted
confirm_tx "$deposit_hash" 30 || { echo "deposit $deposit_hash did not land"; exit 1; }

# vote yes on the proposal
vote_hash=$(qadenad_alias tx gov vote $proposal_id yes --from pioneer1 -y --output json --gas-prices $minimum_gas_prices --gas $gas_auto --gas-adjustment $gas_adjustment | jq -r '.txhash')
echo $vote_hash

# wait for the vote to be submitted
confirm_tx "$vote_hash" 30 || { echo "vote $vote_hash did not land"; exit 1; }