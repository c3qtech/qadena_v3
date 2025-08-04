#!/bin/zsh

set -e


# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

accountCount="30"

createwalletsponsor="create-wallet-sponsor"

identityprovidermnemonic="canoe oppose eternal occur film common dirt tomorrow lottery fun mask quote result account nasty tuna seat miracle have idle trophy frog catalog kiss"
dsvsprovidermnemonic="angry addict suit reform ostrich ride icon cushion park yellow wisdom mobile column sweet use anchor since tragic series ladder asthma dose prosper voice"

provideramount="1000000qdn"
signeramount="10000qdn"
createwalletsponsoramount="100000qdn"

$qadenatestscripts/setup_provider.sh secidentitysrvprv identity --provider-amount $provideramount --provider-mnemonic $identityprovidermnemonic --create-wallet-sponsor $createwalletsponsor --count $accountCount

$qadenatestscripts/setup_provider.sh secdsvssrvprv dsvs --provider-amount $provideramount --provider-mnemonic $dsvsprovidermnemonic --create-wallet-sponsor $createwalletsponsor --count $accountCount

name="secdsvs"
mnemonic="tide ugly fork short cushion girl earth stage anger away pig screen blood frequent link become crowd visa end present share helmet brain fit"
a="100"
bf="5678"
firstname="SEC"
middlename=""
lastname="Signatory"
birthdate="1970-Jan-01"
gender="M"
citizenship="PH"
residency="PH"
email="no-reply@sec.gov.ph"
phone="+63288888800"
serviceprovider="secdsvssrvprv"
identityprovider="secidentitysrvprv"
acceptcredentialtypes=""
acceptpassword=""
requiresendertypes=""
eph_count="$accountCount"

echo "-------------------------"
echo "$name Create wallet (sec-dsvs) -- SEC signers"
echo "-------------------------"

$qadenatestscripts/setup_user.sh $name $mnemonic "pioneer1" "$serviceprovider" "$firstname" "$middlename" "$lastname" $birthdate $citizenship $residency $gender $email $phone $a $bf $identityprovider "$acceptcredentialtypes" "$acceptpassword" "$requiresendertypes" $eph_count $createwalletsponsor
qadena_addr=$(qadenad_alias keys show $name --address)
echo "Sending $signeramount to $qadena_addr from treasury"
result=$(qadenad_alias tx bank send treasury $qadena_addr  $signeramount --from treasury --yes --output json)
echo "Result: $result"
# get tx hash
tx_hash=$(echo $result | jq -r .txhash)
echo "tx hash: $tx_hash"
# wait for result
qadenad_alias query wait-tx $tx_hash --timeout 30s
# fund eph wallets
for i in $(seq 1 $eph_count); do
    qadena_addr=$(qadenad_alias keys show $name-eph$i --address)
    echo "Sending $signeramount to $qadena_addr from treasury"
    result=$(qadenad_alias tx bank send treasury $qadena_addr  $signeramount --from treasury --yes --output json)
    echo "Result: $result"
    # get tx hash
    tx_hash=$(echo $result | jq -r .txhash)
    echo "tx hash: $tx_hash"
    # wait for result
    qadenad_alias query wait-tx $tx_hash --timeout 30s
done

name="sec-create-wallet-sponsor"
mnemonic="barely true danger guilt recipe idle name any blind toast identify mango pilot fork safe clown reveal chalk artefact genuine debate early home concert"
a="200"
lastname="Sponsor"
serviceprovider=""

echo "-------------------------"
echo "$name Create wallet (sec-create-wallet-sponsor)"
echo "-------------------------"

$qadenatestscripts/setup_user.sh $name $mnemonic "pioneer1" "$serviceprovider" "$firstname" "$middlename" "$lastname" $birthdate $citizenship $residency $gender $email $phone $a $bf $identityprovider "$acceptcredentialtypes" "$acceptpassword" "$requiresendertypes" $eph_count $createwalletsponsor
qadena_addr=$(qadenad_alias keys show $name --address)
echo "Sending $createwalletsponsoramount to $qadena_addr from treasury"
result=$(qadenad_alias tx bank send treasury $qadena_addr  $createwalletsponsoramount --from treasury --yes --output json)
echo "Result: $result"
# get tx hash
tx_hash=$(echo $result | jq -r .txhash)
echo "tx hash: $tx_hash"
# wait for result
qadenad_alias query wait-tx $tx_hash --timeout 30s

# fund eph wallets
for i in $(seq 1 $eph_count); do
    qadena_addr=$(qadenad_alias keys show $name-eph$i --address)
    echo "Sending $createwalletsponsoramount to $qadena_addr from treasury"
    result=$(qadenad_alias tx bank send treasury $qadena_addr  $createwalletsponsoramount --from treasury --yes --output json)
    echo "Result: $result"
    # get tx hash
    tx_hash=$(echo $result | jq -r .txhash)
    echo "tx hash: $tx_hash"
    # wait for result
    qadenad_alias query wait-tx $tx_hash --timeout 30s
done


$qadenatestscripts/extract_ephem_keys.sh --provider secidentitysrvprv# --count $accountCount
$qadenatestscripts/extract_ephem_keys.sh --provider secdsvssrvprv# --count $accountCount
$qadenatestscripts/extract_ephem_keys.sh --provider sec-create-wallet-sponsor# --count $accountCount
$qadenatestscripts/extract_ephem_keys.sh --provider secdsvs# --count $accountCount
$qadenatestscripts/extract_ephem_keys.sh --provider secdsvs#-credential --count $accountCount


