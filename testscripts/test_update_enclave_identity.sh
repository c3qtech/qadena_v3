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
submit_hash=$(qadenad_alias tx gov submit-proposal "test_data/$json_proposal.gen.json" --from pioneer1 -y --output json | jq -r '.txhash')
echo $submit_hash

# wait for the proposal to be submitted
qadenad_alias query wait-tx $submit_hash --timeout 30s

# Get the proposal ID
proposal_id=$(qadenad_alias query tx $submit_hash --output json | jq -r '.events[] | select(.type=="submit_proposal") | .attributes[] | select(.key=="proposal_id") | .value')
echo $proposal_id

# deposit into the proposal
deposit_hash=$(qadenad_alias tx gov deposit $proposal_id 1000qdn --from pioneer1 -y --output json | jq -r '.txhash')
echo $deposit_hash

# wait for the deposit to be submitted
qadenad_alias query wait-tx $deposit_hash --timeout 30s

# vote yes on the proposal
vote_hash=$(qadenad_alias tx gov vote $proposal_id yes --from pioneer1 -y --output json | jq -r '.txhash')
echo $vote_hash

# wait for the vote to be submitted
qadenad_alias query wait-tx $vote_hash --timeout 30s