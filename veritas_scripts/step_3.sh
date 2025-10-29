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

# read mnemonics from json file
createwalletsponsormnemonic=$(jq -r .createwalletsponsormnemonic mnemonics.json)
signermnemonic=$(jq -r .signermnemonic mnemonics.json)

# read proposal id from secidentity.proposal_id
identityproposal_id=$(cat $qadenaproviderscripts/proposals/secidentitysrvprv.proposal_id)
dsvsproposal_id=$(cat $qadenaproviderscripts/proposals/secdsvssrvprv.proposal_id)
echo "Waiting for approval of providers"

$qadenaproviderscripts/query_service_provider_proposal.sh $identityproposal_id --wait
$qadenaproviderscripts/query_service_provider_proposal.sh $dsvsproposal_id --wait

echo "Providers approved"


########################################################
# Create wallet sponsor
########################################################

name="sec-create-wallet-sponsor"
echo "-------------------------"
echo "Setting up $name"
echo "-------------------------"

mnemonic=$createwalletsponsormnemonic
a="200"
bf="5678"
firstname="SEC"
middlename=""
lastname="Create Wallet Sponsor"
birthdate="1936-Oct-26"
gender="M"
citizenship="PH"
residency="PH"
email="no-reply@sec.gov.ph"
phone="+63288888800"
identityprovider="secidentitysrvprv"
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

$qadenaproviderscripts/create_user.sh $name $mnemonic $pioneer "$dsvsserviceprovider" "$firstname" "$middlename" "$lastname" $birthdate $citizenship $residency $gender $email $phone $a $bf "$identityprovider" "$acceptcredentialtypes" "$acceptpassword" "$requiresendertypes" $eph_count "sec-treasury"
qadena_addr=$(qadenad_alias keys show $name --address)
echo "Sending $per_account_amount to $qadena_addr from sec-treasury"
result=$(qadenad_alias tx bank send sec-treasury $qadena_addr  $per_account_amount --from sec-treasury --yes --output json --gas-prices $minimum_gas_prices --gas auto --gas-adjustment $gas_adjustment)
echo "Result: $result"
# get tx hash
tx_hash=$(echo $result | jq -r .txhash)
echo "tx hash: $tx_hash"
# wait for result
result=$(qadenad_alias query wait-tx $tx_hash --output json --timeout 30s)
echo "Result: $result"
if [ $(echo $result | jq -r .code) -ne 0 ]; then
    echo "Failed to send $per_account_amount to $qadena_addr from sec-treasury"
    exit 1
fi

# fund eph wallets
for i in $(seq 1 $eph_count); do
    qadena_addr=$(qadenad_alias keys show $name-eph$i --address)
    echo "Sending $per_account_amount to $qadena_addr from sec-treasury"
    result=$(qadenad_alias tx bank send sec-treasury $qadena_addr  $per_account_amount --from sec-treasury --yes --output json --gas-prices $minimum_gas_prices --gas auto --gas-adjustment $gas_adjustment)
    echo "Result: $result"
    # get tx hash
    tx_hash=$(echo $result | jq -r .txhash)
    echo "tx hash: $tx_hash"
    # wait for result
    result=$(qadenad_alias query wait-tx $tx_hash --output json --timeout 30s)
    echo "Result: $result"
    if [ $(echo $result | jq -r .code) -ne 0 ]; then
        echo "Failed to send $per_account_amount to $qadena_addr from sec-treasury"
        exit 1
    fi
done


name="secdsvs"
echo "-------------------------"
echo "Setting up $name"
echo "-------------------------"

mnemonic=$signermnemonic
a="100"
bf="5678"
firstname="SEC"
middlename=""
lastname="Signatory"
birthdate="1936-Oct-26"
gender="F"
citizenship="PH"
residency="PH"
email="no-reply@sec.gov.ph"
phone="+63288888800"
dsvsserviceprovider="secdsvssrvprv"
identityprovider="secidentitysrvprv"
acceptcredentialtypes=""
acceptpassword=""
requiresendertypes=""
eph_count="$count"

$qadenaproviderscripts/create_user.sh $name $mnemonic $pioneer "$dsvsserviceprovider" "$firstname" "$middlename" "$lastname" $birthdate $citizenship $residency $gender $email $phone $a $bf $identityprovider "$acceptcredentialtypes" "$acceptpassword" "$requiresendertypes" $eph_count "sec-treasury"
qadena_addr=$(qadenad_alias keys show $name --address)
echo "Sending $signeramount to $qadena_addr from sec-treasury"
result=$(qadenad_alias tx bank send sec-treasury $qadena_addr  $signeramount --from sec-treasury --yes --output json --gas-prices $minimum_gas_prices --gas auto --gas-adjustment $gas_adjustment)
echo "Result: $result"
# get tx hash
tx_hash=$(echo $result | jq -r .txhash)
echo "tx hash: $tx_hash"
# wait for result
result=$(qadenad_alias query wait-tx $tx_hash --output json --timeout 30s)
echo "Result: $result"
if [ $(echo $result | jq -r .code) -ne 0 ]; then
    echo "Failed to send $signeramount to $qadena_addr from sec-treasury"
    exit 1
fi
# fund eph wallets
for i in $(seq 1 $eph_count); do
    qadena_addr=$(qadenad_alias keys show $name-eph$i --address)
    echo "Sending $signeramount to $qadena_addr from sec-treasury"
    result=$(qadenad_alias tx bank send sec-treasury $qadena_addr  $signeramount --from sec-treasury --yes --output json --gas-prices $minimum_gas_prices --gas auto --gas-adjustment $gas_adjustment)
    echo "Result: $result"
    # get tx hash
    tx_hash=$(echo $result | jq -r .txhash)
    echo "tx hash: $tx_hash"
    # wait for result
    result=$(qadenad_alias query wait-tx $tx_hash --output json --timeout 30s)
    echo "Result: $result"
    if [ $(echo $result | jq -r .code) -ne 0 ]; then
        echo "Failed to send $signeramount to $qadena_addr from sec-treasury"
        exit 1
    fi
done

$qadenatestscripts/extract_ephem_keys.sh --provider secidentitysrvprv# --count $count
$qadenatestscripts/extract_ephem_keys.sh --provider secdsvssrvprv# --count $count
$qadenatestscripts/extract_ephem_keys.sh --provider sec-create-wallet-sponsor# --count $count
$qadenatestscripts/extract_ephem_keys.sh --provider secdsvs# --count $count
$qadenatestscripts/extract_ephem_keys.sh --provider secdsvs#-credential --count $count





