#!/bin/zsh

nodeid=$1
json_proposal=$2
service_provider_type=$3

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

if [ -z $nodeid ] || [ -z $json_proposal ] ; then
    echo "Usage: ./test_submit_service_provider_proposal.sh <nodeid> <json_proposal> (e.g. add_service_provider_proposal, deactivate_service_provider_proposal) <service_provider_type> (optional:  e.g. identity, finance)"
    exit 1
fi

cd $qadenabuild

# check if address already exists
address=$(qadenad_alias keys show $nodeid --output json --keyring-backend test 2> /dev/null| jq -r '.address')
if [ -z $address ] ; then
    echo "Address not found: $nodeid, creating one..."
    address=`qadenad_alias keys add $nodeid --output json --keyring-backend test | jq -r '.address'`
fi

# modify json_proposal
jq --arg nodeid "$nodeid" \
   '.messages[0].nodeID = $nodeid' \
   "test_data/$json_proposal.json" > "test_data/$json_proposal.gen.json"


# check if the proposal has pubKID set
pubKID=$(cat "test_data/$json_proposal.json" | jq -r '.messages[0].pubKID // empty')
echo "pubKID: $pubKID"
if [ -n "$pubKID" ] ; then
    echo "pubKID found in proposal, setting it to $address"
    jq --arg address "$address" '.messages[0].pubKID = $address' "test_data/$json_proposal.gen.json" > "test_data/$json_proposal-1.gen.json"
    mv "test_data/$json_proposal-1.gen.json" "test_data/$json_proposal.gen.json"
fi



# check if the proposal has serviceProviderType set
serviceProviderType=$(cat "test_data/$json_proposal.json" | jq -r '.messages[0].serviceProviderType // empty')
if [ -n "$serviceProviderType" ] ; then
    if [ -z $service_provider_type ] ; then
        echo "Error: serviceProviderType found in proposal but it was not provided"
        exit 10
    fi
    echo "serviceProviderType found in proposal, setting it to $service_provider_type"
    jq --arg service_provider_type "$service_provider_type" '.messages[0].serviceProviderType = $service_provider_type' "test_data/$json_proposal.gen.json" > "test_data/$json_proposal-1.gen.json"
    mv "test_data/$json_proposal-1.gen.json" "test_data/$json_proposal.gen.json"
fi

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

# wait until proposal is passed
while true; do
    stat=$(qadenad_alias query gov proposal $proposal_id --output json | jq -r '.proposal.status')
    if [ "$stat" = "3" ]; then
        echo "Proposal $proposal_id passed"
        break
    fi
    echo "Waiting for proposal $proposal_id to pass..."
    sleep 3
done
