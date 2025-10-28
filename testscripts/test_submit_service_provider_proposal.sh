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

echo "-------------------------"
echo "Submit proposal"
echo "-------------------------"


# submit json_proposal
result=$(qadenad_alias tx gov submit-proposal "test_data/$json_proposal.gen.json" --from pioneer1 -y --output json --gas-prices $minimum_gas_prices --gas auto --gas-adjustment $gas_adjustment)
echo "Result: $result"
submit_hash=$(echo $result | jq -r .txhash)
# check if code is 0
if [ $(echo $result | jq -r .code) -ne 0 ]; then
    echo "Error: $(echo $result | jq -r .message)"
    exit 1
fi

echo "submit_hash: $submit_hash"
# wait for the proposal to be submitted
qadenad_alias query wait-tx $submit_hash --timeout 30s

# Get the proposal ID
proposal_id=$(qadenad_alias query tx $submit_hash --output json | jq -r '.events[] | select(.type=="submit_proposal") | .attributes[] | select(.key=="proposal_id") | .value')
echo "proposal_id: $proposal_id"

echo "-------------------------"
echo "Deposit into proposal"
echo "-------------------------"

# deposit into the proposal
result=$(qadenad_alias tx gov deposit $proposal_id 1000qdn --from pioneer1 -y --output json --gas-prices $minimum_gas_prices --gas auto --gas-adjustment $gas_adjustment)
echo "Result: $result"
deposit_hash=$(echo $result | jq -r .txhash)
# check if code is 0
if [ $(echo $result | jq -r .code) -ne 0 ]; then
    echo "Error: $(echo $result | jq -r .message)"
    exit 1
fi
echo "deposit_hash: $deposit_hash"

# wait for the deposit to be submitted
result=$(qadenad_alias query wait-tx $deposit_hash --output json --timeout 30s)
echo "Result: $result"

# check if code is 0
if [ $(echo $result | jq -r .code) -ne 0 ]; then
    echo "Error: $(echo $result | jq -r .message)"
    exit 1
fi

$qadenaproviderscripts/query_service_provider_proposal.sh $proposal_id --wait --status "PROPOSAL_STATUS_VOTING_PERIOD"

# vote yes on the proposal
gas_adjustment="2.0"
result=$(qadenad_alias tx gov vote $proposal_id yes --from pioneer1 -y --output json --gas-prices $minimum_gas_prices --gas auto --gas-adjustment $gas_adjustment)
echo "Result: $result"
# check if code is 0
if [ $(echo $result | jq -r .code) -ne 0 ]; then
    echo "Error: $(echo $result | jq -r .message)"
    exit 1
fi

# wait for the vote to be submitted
vote_hash=$(echo $result | jq -r .txhash)
result=$(qadenad_alias query wait-tx $vote_hash --output json --timeout 30s)
echo "Result: $result"

# check if code is 0
if [ $(echo $result | jq -r .code) -ne 0 ]; then
    echo "Error: $(echo $result | jq -r .message)"
    exit 1
fi

# wait until proposal is passed
while true; do
    stat=$(qadenad_alias query gov proposal $proposal_id --output json | jq -r '.proposal.status')
    if [ "$stat" = "PROPOSAL_STATUS_PASSED" ]; then
        echo "Proposal $proposal_id passed"
        break
    fi
    echo "Date: $(date -z UTC)"
    echo "Proposal is:  $proposal_id $(qadenad_alias query gov proposal $proposal_id --output json)"
    echo "Waiting for proposal $proposal_id to pass..."
    sleep 3
done
