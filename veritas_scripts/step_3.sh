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
identityprovidername=$(jq -r .identityprovidername variables.json)
dsvsprovidername=$(jq -r .dsvsprovidername variables.json)
createwalletsponsorname=$(jq -r .createwalletsponsorname variables.json)
dsvsname=$(jq -r .dsvsname variables.json)
email=$(jq -r .email variables.json)
avalue=$(jq -r .avalue variables.json)
phone=$(jq -r .phone variables.json)
firstname=$(jq -r .firstname variables.json)
birthdate=$(jq -r .birthdate variables.json)
treasuryname=$(jq -r .treasuryname variables.json)




# read mnemonics from json file
createwalletsponsormnemonic=$(jq -r .createwalletsponsormnemonic mnemonics.json)
signermnemonic=$(jq -r .signermnemonic mnemonics.json)

# read proposal id from identityprovidername.proposal_id
identityproposal_id=$(cat $qadenaproviderscripts/proposals/$identityprovidername.proposal_id)
dsvsproposal_id=$(cat $qadenaproviderscripts/proposals/$dsvsprovidername.proposal_id)
echo "Waiting for approval of providers"

$qadenaproviderscripts/query_service_provider_proposal.sh $identityproposal_id --wait
$qadenaproviderscripts/query_service_provider_proposal.sh $dsvsproposal_id --wait

echo "Providers approved"


########################################################
# Create wallet sponsor
########################################################

name="$createwalletsponsorname"
echo "-------------------------"
echo "Setting up $name"
echo "-------------------------"

mnemonic=$createwalletsponsormnemonic
a="$avalue"
bf="5678"
middlename=""
lastname="Create Wallet Sponsor"
gender="M"
citizenship="PH"
residency="PH"
identityprovider="$identityprovidername"
dsvsserviceprovider=""
acceptcredentialtypes=""
acceptpassword=""
requiresendertypes=""
eph_count="$count"

# compute per-account amount
if [ $count -gt 0 ]; then
    echo "count is greater than 0"
    # Extract numeric prefix (digits)
    numeric_part=${createwalletsponsoramount%%[!0-9]*}

    # Extract suffix (non-digits after the number)
    token_suffix=${createwalletsponsoramount#$numeric_part}

    # Divide
    per_account_amount=$(( numeric_part / (count + 1) ))$token_suffix

    # Output
    echo "per_account_amount: $per_account_amount"
else
    echo "count is 0"
    per_account_amount=$createwalletsponsoramount
fi

echo "create-user.sh" $name $mnemonic $pioneer "$dsvsserviceprovider" "$firstname" "$middlename" "$lastname" $birthdate $citizenship $residency $gender $email $phone $a $bf "$identityprovider" "$acceptcredentialtypes" "$acceptpassword" "$requiresendertypes" $eph_count "$treasuryname"

$qadenaproviderscripts/create_user.sh $name $mnemonic $pioneer "$dsvsserviceprovider" "$firstname" "$middlename" "$lastname" $birthdate $citizenship $residency $gender $email $phone $a $bf "$identityprovider" "$acceptcredentialtypes" "$acceptpassword" "$requiresendertypes" $eph_count "$treasuryname"
qadena_addr=$(qadenad_alias keys show $name --address)
echo "Sending $per_account_amount to $qadena_addr from $treasuryname"
result=$(qadenad_alias tx bank send $treasuryname $qadena_addr  $per_account_amount --from $treasuryname --yes --output json --gas-prices $minimum_gas_prices --gas auto --gas-adjustment $gas_adjustment)
echo "Result: $result"
# get tx hash
tx_hash=$(echo $result | jq -r .txhash)
echo "tx hash: $tx_hash"
# wait for result
result=$(qadenad_alias query wait-tx $tx_hash --output json --timeout 30s)
echo "Result: $result"
if [ $(echo $result | jq -r .code) -ne 0 ]; then
    echo "Failed to send $per_account_amount to $qadena_addr from $treasuryname"
    exit 1
fi

# fund eph wallets
for i in $(seq 1 $eph_count); do
    qadena_addr=$(qadenad_alias keys show $name-eph$i --address)
    echo "Sending $per_account_amount to $qadena_addr from $treasuryname"
    result=$(qadenad_alias tx bank send $treasuryname $qadena_addr  $per_account_amount --from $treasuryname --yes --output json --gas-prices $minimum_gas_prices --gas auto --gas-adjustment $gas_adjustment)
    echo "Result: $result"
    # get tx hash
    tx_hash=$(echo $result | jq -r .txhash)
    echo "tx hash: $tx_hash"
    # wait for result
    result=$(qadenad_alias query wait-tx $tx_hash --output json --timeout 30s)
    echo "Result: $result"
    if [ $(echo $result | jq -r .code) -ne 0 ]; then
        echo "Failed to send $per_account_amount to $qadena_addr from $treasuryname"
        exit 1
    fi
done


name="$dsvsname"
echo "-------------------------"
echo "Setting up $name"
echo "-------------------------"

mnemonic=$signermnemonic
# add 1 to avalue
avalue=$((avalue + 1))
a="$avalue"
bf="5678"
middlename=""
gender="F"
citizenship="PH"
residency="PH"
dsvsserviceprovider="$dsvsprovidername"
identityprovider="$identityprovidername"
acceptcredentialtypes=""
acceptpassword=""
requiresendertypes=""
eph_count="$count"

# compute per-account amount
if [ $count -gt 0 ]; then
    echo "count is greater than 0"
    # Extract numeric prefix (digits)
    numeric_part=${signeramount%%[!0-9]*}

    # Extract suffix (non-digits after the number)
    token_suffix=${signeramount#$numeric_part}

    # Divide
    per_account_amount=$(( numeric_part / (count + 1) ))$token_suffix

    # Output
    echo "per_account_amount: $per_account_amount"
else
    echo "count is 0"
    per_account_amount=$signeramount
fi

$qadenaproviderscripts/create_user.sh $name $mnemonic $pioneer "$dsvsserviceprovider" "$firstname" "$middlename" "$lastname" $birthdate $citizenship $residency $gender $email $phone $a $bf $identityprovider "$acceptcredentialtypes" "$acceptpassword" "$requiresendertypes" $eph_count "$treasuryname"
qadena_addr=$(qadenad_alias keys show $name --address)
echo "Sending $per_account_amount to $qadena_addr from $treasuryname"
result=$(qadenad_alias tx bank send $treasuryname $qadena_addr  $per_account_amount --from $treasuryname --yes --output json --gas-prices $minimum_gas_prices --gas auto --gas-adjustment $gas_adjustment)
echo "Result: $result"
# get tx hash
tx_hash=$(echo $result | jq -r .txhash)
echo "tx hash: $tx_hash"
# wait for result
result=$(qadenad_alias query wait-tx $tx_hash --output json --timeout 30s)
echo "Result: $result"
if [ $(echo $result | jq -r .code) -ne 0 ]; then
    echo "Failed to send $per_account_amount to $qadena_addr from $treasuryname"
    exit 1
fi
# fund eph wallets
for i in $(seq 1 $eph_count); do
    qadena_addr=$(qadenad_alias keys show $name-eph$i --address)
    echo "Sending $per_account_amount to $qadena_addr from $treasuryname"
    result=$(qadenad_alias tx bank send $treasuryname $qadena_addr  $per_account_amount --from $treasuryname --yes --output json --gas-prices $minimum_gas_prices --gas auto --gas-adjustment $gas_adjustment)
    echo "Result: $result"
    # get tx hash
    tx_hash=$(echo $result | jq -r .txhash)
    echo "tx hash: $tx_hash"
    # wait for result
    result=$(qadenad_alias query wait-tx $tx_hash --output json --timeout 30s)
    echo "Result: $result"
    if [ $(echo $result | jq -r .code) -ne 0 ]; then
        echo "Failed to send $per_account_amount to $qadena_addr from $treasuryname"
        exit 1
    fi
done

$qadenatestscripts/extract_ephem_keys.sh --provider $identityprovidername# --count $count --include-base-provider --include-base-provider-credential
$qadenatestscripts/extract_ephem_keys.sh --provider $dsvsprovidername# --count $count --include-base-provider
$qadenatestscripts/extract_ephem_keys.sh --provider $createwalletsponsorname# --count $count --include-base-provider
$qadenatestscripts/extract_ephem_keys.sh --provider $dsvsname# --count $count
$qadenatestscripts/extract_ephem_keys.sh --provider $dsvsname#-credential --count $count





