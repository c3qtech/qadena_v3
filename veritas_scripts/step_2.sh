#!/bin/zsh

set -e


# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"


# read variables from json file
provideramount=$(jq -r .provideramount variables.json)
signeramount=$(jq -r .signeramount variables.json)
createwalletsponsoramount=$(jq -r .createwalletsponsoramount variables.json)
pioneer=$(jq -r .pioneer variables.json)
count=$(jq -r .count variables.json)
treasuryname=$(jq -r .treasuryname variables.json)
identityprovidername=$(jq -r .identityprovidername variables.json)
dsvsprovidername=$(jq -r .dsvsprovidername variables.json)

echo "treasuryname: $treasuryname"
echo "provideramount: $provideramount"
echo "signeramount: $signeramount"
echo "createwalletsponsoramount: $createwalletsponsoramount"
echo "pioneer: $pioneer"
echo "count: $count"

# read mnemonics from json file
identityprovidermnemonic=$(jq -r .identityprovidermnemonic mnemonics.json)
dsvsprovidermnemonic=$(jq -r .dsvsprovidermnemonic mnemonics.json)

echo "identityprovidermnemonic: $identityprovidermnemonic"
echo "dsvsprovidermnemonic: $dsvsprovidermnemonic"



# wait until there are funds in $treasuryname
echo "Waiting for funds in $treasuryname"
while [ "$(qadenad_alias query bank balances $treasuryname --output json | jq -r ".balances[0].amount // empty")" = "" ] || [ "$(qadenad_alias query bank balances $treasuryname --output json | jq -r ".balances[0].amount")" = "null" ] || [ "$(qadenad_alias query bank balances $treasuryname --output json | jq -r ".balances[0].amount")" = "0" ]; do
    sleep 1
echo "Checking again:  Waiting for funds in $treasuryname"
done

echo "Funds in $treasuryname: $(qadenad_alias query bank balances $treasuryname --output json | jq -r ".balances[0].amount")"

# setup identity provider
echo "-------------------------"
echo "Setting up $identityprovidername provider"
echo "-------------------------"

$qadenaproviderscripts/setup_provider_base.sh $identityprovidername identity --pioneer $pioneer --treasury $treasuryname --provider-mnemonic $identityprovidermnemonic --provider-amount $provideramount --count $count

# load proposal id from identity.proposal_id
identityproposal_id=$(cat $qadenaproviderscripts/proposals/$identityprovidername.proposal_id)

$qadenaproviderscripts/query_service_provider_proposal.sh $identityproposal_id --wait --status "PROPOSAL_STATUS_VOTING_PERIOD"


# setup dsvs provider
echo "-------------------------"
echo "Setting up  $dsvsprovidername provider"
echo "-------------------------"

$qadenaproviderscripts/setup_provider_base.sh $dsvsprovidername dsvs --pioneer $pioneer --treasury $treasuryname --provider-mnemonic $dsvsprovidermnemonic --provider-amount $provideramount --count $count

# load proposal id from dsvssrvprv.proposal_id
dsvsproposal_id=$(cat $qadenaproviderscripts/proposals/$dsvsprovidername.proposal_id)

$qadenaproviderscripts/query_service_provider_proposal.sh $dsvsproposal_id --wait --status "PROPOSAL_STATUS_VOTING_PERIOD"

echo "Send the following information to QFI"
echo "$identityprovidername proposal_id: $identityproposal_id"
echo "$dsvsprovidername proposal_id: $dsvsproposal_id"

echo "QFI will inform you when the providers are approved."
echo "Once approved, run $veritasscripts/step_3.sh"


