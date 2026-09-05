#!/bin/zsh

treasury=$1
providername=$2
json_proposal=$3
service_provider_type=$4
pioneer=${5:-${QADENA_PIONEER:-pioneer1}}

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

if [ -z $providername ] || [ -z $json_proposal ] ; then
    echo "Usage: submit_service_provider_proposal.sh <treasury> <providername> <proposal_type> (e.g. add_service_provider_proposal, deactivate_service_provider_proposal) <service_provider_type> (optional:  e.g. identity, finance) <pioneer> (optional: defaults to \$QADENA_PIONEER or pioneer1)"
    exit 1
fi

# check if address already exists
# NO SECOND --keyring-backend HERE.  qadenad_alias already supplies the backend AND the keyring
# directory, and passing `test` again overrode both -- so with SEC's keys in
# $VERITAS_SEC_HOME/keyring this looked in the node's keyring instead and found nothing.  An empty
# address then flowed into the proposal as a blank field.
address=$(qadenad_alias keys show $providername --output json 2> /dev/null | jq -r '.address')
if [ -z $address ] ; then
    echo "Address not found: $providername"
    exit 1
fi

# if $qadenaproviderscripts/proposals does not exist, create it
if [ ! -d "$qadenaproviderscripts/proposals" ]; then
    mkdir "$qadenaproviderscripts/proposals"
fi


# modify json_proposal
# homePioneerID is substituted for the SAME reason nodeID is.  The template carries a literal
# `pioneer1` -- correct on the devnet, wrong on any chain whose genesis validator is named
# something else, and the generator used to copy it through untouched.  Nothing rejects it at
# proposal time: the registration passes governance and looks healthy for the life of the chain.
# It fails much later and somewhere else entirely -- sign-recover-key resolves the PROVIDER'S
# home pioneer to sign a recovery share, GetIntervalPublicKey misses, and the operator sees
# `key not found` naming neither the provider nor the pioneer.  And it is UNRECOVERABLE:
# AddServiceProvider refuses an existing nodeID (ErrServiceProviderAlreadyExists) and deactivate
# overwrites rather than deletes, so the name is burned with the wrong pioneer baked in.
jq --arg nodeid "$providername" --arg pioneer "$pioneer" \
   '.messages[0].nodeID = $nodeid | .messages[0].homePioneerID = $pioneer' \
   "$qadenaproviderscripts/templates/$json_proposal.json" > "$qadenaproviderscripts/proposals/$providername.gen.json"


# check if the proposal has pubKID set
pubKID=$(cat "$qadenaproviderscripts/proposals/$providername.gen.json" | jq -r '.messages[0].pubKID // empty')
echo "pubKID: $pubKID"
if [ -n "$pubKID" ] ; then
    echo "pubKID found in proposal, setting it to $address"
    jq --arg address "$address" '.messages[0].pubKID = $address' "$qadenaproviderscripts/proposals/$providername.gen.json" > "$qadenaproviderscripts/proposals/$providername-1.gen.json"
    mv "$qadenaproviderscripts/proposals/$providername-1.gen.json" "$qadenaproviderscripts/proposals/$providername.gen.json"
fi

# check if the proposal has serviceProviderType set
serviceProviderType=$(cat "$qadenaproviderscripts/proposals/$providername.gen.json" | jq -r '.messages[0].serviceProviderType // empty')
if [ -n "$serviceProviderType" ] ; then
    if [ -z $service_provider_type ] ; then
        echo "Error: serviceProviderType found in proposal but it was not provided"
        exit 10
    fi
    echo "serviceProviderType found in proposal, setting it to $service_provider_type"
    jq --arg service_provider_type "$service_provider_type" '.messages[0].serviceProviderType = $service_provider_type' "$qadenaproviderscripts/proposals/$providername.gen.json" > "$qadenaproviderscripts/proposals/$providername-1.gen.json"
    mv "$qadenaproviderscripts/proposals/$providername-1.gen.json" "$qadenaproviderscripts/proposals/$providername.gen.json"
fi

echo "-------------------------"
echo "Submit proposal"
echo "-------------------------"


# submit json_proposal
result=$(qadenad_alias tx gov submit-proposal "$qadenaproviderscripts/proposals/$providername.gen.json" --from $treasury -y --output json --gas-prices $minimum_gas_prices --gas auto --gas-adjustment $gas_adjustment)
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
result=$(qadenad_alias tx gov deposit $proposal_id 100000qdn --from $treasury -y --output json --gas-prices $minimum_gas_prices --gas auto --gas-adjustment $gas_adjustment)
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
if [ $(echo $result | jq -r .code) -ne 0 ]; then
    echo "Error: $(echo $result | jq -r .message)"
    exit 1
fi

# get deposit status
deposits=$(qadenad_alias query gov deposits $proposal_id --output json)
echo "Deposits: $deposits"

# get proposal status
proposal=$(qadenad_alias query gov proposal $proposal_id --output json)
echo "Proposal: $proposal"

# save proposal id
echo "$proposal_id" > $qadenaproviderscripts/proposals/$providername.proposal_id

