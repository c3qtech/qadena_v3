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



# wait until there are funds in sec-treasury
echo "Waiting for funds in sec-treasury"
while [ "$(qadenad_alias query bank balances sec-treasury --output json | jq -r ".balances[0].amount // empty")" = "" ] || [ "$(qadenad_alias query bank balances sec-treasury --output json | jq -r ".balances[0].amount")" = "null" ] || [ "$(qadenad_alias query bank balances sec-treasury --output json | jq -r ".balances[0].amount")" = "0" ]; do
    sleep 1
echo "Checking again:  Waiting for funds in sec-treasury"
done

echo "Funds in sec-treasury: $(qadenad_alias query bank balances sec-treasury --output json | jq -r ".balances[0].amount")"

# setup identity provider
echo "-------------------------"
echo "Setting up secidentitysrvprv provider"
echo "-------------------------"

$qadenaproviderscripts/setup_provider_base.sh secidentitysrvprv identity --pioneer $pioneer --treasury sec-treasury --provider-mnemonic $identityprovidermnemonic --provider-amount $provideramount --count $count

# load proposal id from secidentity.proposal_id
identityproposal_id=$(cat $qadenaproviderscripts/proposals/secidentitysrvprv.proposal_id)

$qadenaproviderscripts/query_service_provider_proposal.sh $identityproposal_id --wait --status "PROPOSAL_STATUS_VOTING_PERIOD"


# setup dsvs provider
echo "-------------------------"
echo "Setting up secdsvssrvprv provider"
echo "-------------------------"

$qadenaproviderscripts/setup_provider_base.sh secdsvssrvprv dsvs --pioneer $pioneer --treasury sec-treasury --provider-mnemonic $dsvsprovidermnemonic --provider-amount $provideramount --count $count

# load proposal id from secdsvssrvprv.proposal_id
dsvsproposal_id=$(cat $qadenaproviderscripts/proposals/secdsvssrvprv.proposal_id)

$qadenaproviderscripts/query_service_provider_proposal.sh $dsvsproposal_id --wait --status "PROPOSAL_STATUS_VOTING_PERIOD"

echo "Send the following information to QFI"
echo "secidentitysrvprv proposal_id: $identityproposal_id"
echo "secdsvssrvprv proposal_id: $dsvsproposal_id"

echo "QFI will inform you when the providers are approved."
echo "Once approved, run $veritasscripts/step_3.sh"


