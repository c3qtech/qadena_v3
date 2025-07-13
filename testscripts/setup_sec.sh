#!/bin/zsh

set -e


# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

accountCount="30"

createwalletsponsor="create-wallet-sponsor"

identityprovidermnemonic="canoe oppose eternal occur film common dirt tomorrow lottery fun mask quote result account nasty tuna seat miracle have idle trophy frog catalog kiss"
dsvsprovidermnemonic="angry addict suit reform ostrich ride icon cushion park yellow wisdom mobile column sweet use anchor since tragic series ladder asthma dose prosper voice"
$qadenatestscripts/setup_provider.sh secidentitysrvprv identity --provider-mnemonic $identityprovidermnemonic --create-wallet-sponsor $createwalletsponsor --count $accountCount
$qadenatestscripts/setup_provider.sh secdsvssrvprv dsvs --provider-mnemonic $dsvsprovidermnemonic --create-wallet-sponsor $createwalletsponsor --count $accountCount

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

$qadenatestscripts/setup_user.sh $name $mnemonic "pioneer1" "$serviceprovider" "$firstname" "$middlename" "$lastname" $birthdate $citizenship $residency $gender $email $phone $a $bf $identityprovider "$acceptcredentialtypes" "$acceptpassword" "$requiresendertypes" $eph_count $createwalletsponsor
# fund eph wallets
for i in $(seq 1 $eph_count); do
    qadena_addr=$(qadenad_alias keys show $name-eph$i --address)
    result=$(qadenad_alias tx bank send treasury $qadena_addr  10000000qdn --from treasury --yes --output json)
    # get tx hash
    tx_hash=$(echo $result | jq -r .txhash)
    echo "tx hash: $tx_hash"
    # wait for result
    qadenad_alias query wait-tx $tx_hash
done

name="sec-create-wallet-sponsor"
mnemonic="barely true danger guilt recipe idle name any blind toast identify mango pilot fork safe clown reveal chalk artefact genuine debate early home concert"
a="200"
lastname="Sponsor"
serviceprovider=""

$qadenatestscripts/setup_user.sh $name $mnemonic "pioneer1" "$serviceprovider" "$firstname" "$middlename" "$lastname" $birthdate $citizenship $residency $gender $email $phone $a $bf $identityprovider "$acceptcredentialtypes" "$acceptpassword" "$requiresendertypes" $eph_count $createwalletsponsor
# fund eph wallets
for i in $(seq 1 $eph_count); do
    qadena_addr=$(qadenad_alias keys show $name-eph$i --address)
    result=$(qadenad_alias tx bank send treasury $qadena_addr  10000000000qdn --from treasury --yes --output json)
    # get tx hash
    tx_hash=$(echo $result | jq -r .txhash)
    echo "tx hash: $tx_hash"
    # wait for result
    qadenad_alias query wait-tx $tx_hash
done


$qadenatestscripts/extract_ephem_keys.sh --provider secidentitysrvprv
$qadenatestscripts/extract_ephem_keys.sh --provider secdsvssrvprv
$qadenatestscripts/extract_ephem_keys.sh --provider sec-create-wallet-sponsor
$qadenatestscripts/extract_ephem_keys.sh --provider secdsvs


