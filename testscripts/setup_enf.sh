#!/bin/zsh

set -e

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"



# inputs

enftreasurymnemonic="crack daughter sister dismiss wall diagram order ready divorce upset anger tomato defense season diesel evolve praise window leopard desk shift fiscal sister blouse"
signermnemonic="correct manage autumn another pass surround item bag educate like bus ugly come such hidden can nasty reason result left clap reject border unit"
createwalletsponsormnemonic="thank omit float build virus oblige tonight slot embark jump actual culture hunt describe stove day decrease breeze card brush danger moral force banner"
identityprovidermnemonic="eye staff snap onion tobacco space phone unfair busy galaxy butter focus puzzle tell patient annual imitate floor town throw shop pizza hungry away"
dsvsprovidermnemonic="depart roast ice mimic gate mass nice practice purse exit force pigeon letter ranch inflict spice potato rent unaware outside observe onion broom decline"


config_yml_treasurymnemonic="eyebrow unaware jealous actor annual farm radio open sword memory other secret twelve reduce festival buddy peace fun film return sniff december february post"

# check if "treasury" key exists by "qadenad "
if qadenad_alias keys show treasury > /dev/null 2>&1; then
    echo "treasury key already exists"
else
    echo "treasury key not found, adding it now"
    echo $config_yml_treasurymnemonic | qadenad_alias keys add treasury --recover
fi


provideramount="100000qdn"
signeramount="100000qdn"
createwalletsponsoramount="100000qdn"


pioneer="pioneer1"

ekycphidentityprovidername="ekycphidentitysrvprv"
treasuryname="enf-treasury"
identityprovidername="enfidentitysrvprv"
dsvsprovidername="enfdsvssrvprv"
dsvsname="enfdsvs"
createwalletsponsorname="enf-create-wallet-sponsor"
email="no-repy@enf.ph"
avalue="2100"
firstname="ENF"

birthdate="2025-Jan-01"
phone="+6320000000"

# accept 1 parameter, the pioneer name
# accept named parameters to override all these mnemonics
# Process command line arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --pioneer)
            pioneer="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [--pioneer <pioneer>]"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--pioneer <pioneer>]"
            exit 1
            ;;
    esac
done

# check if ekycphidentityprovidername key exists
if qadenad_alias keys show $ekycphidentityprovidername > /dev/null 2>&1; then
    echo "$ekycphidentityprovidername key already exists"
else
    echo "$ekycphidentityprovidername key not found, setting up ekycph..."
    $qadenatestscripts/setup_ekycph.sh
fi

#
count=2

echo "-------------------------"
echo "Staking from treasury to $pioneer"
echo "-------------------------"

# need to stake from treasury to pioneer1, do this only once
$qadenatestscripts/gov_stake_from_treasury.sh $pioneer 10000000qdn


$veritasscripts/step_1.sh --count $count --provideramount $provideramount --signeramount $signeramount --createwalletsponsoramount $createwalletsponsoramount --createwalletsponsorname $createwalletsponsorname --pioneer $pioneer --treasurymnemonic $enftreasurymnemonic --signermnemonic $signermnemonic --createwalletsponsormnemonic $createwalletsponsormnemonic --identityprovidermnemonic $identityprovidermnemonic --dsvsprovidermnemonic $dsvsprovidermnemonic --treasuryname $treasuryname --identityprovidername $identityprovidername --dsvsprovidername $dsvsprovidername --email $email --avalue $avalue --firstname $firstname --birthdate $birthdate --phone $phone --dsvsname $dsvsname


# grants 2M qdn from "treasury" to "enf-treasury"
echo "-------------------------"
echo "Granting 2M qdn from treasury to enf-treasury"
echo "-------------------------"
$qadenatestscripts/grant_from_treasury.sh $treasuryname 2000000qdn

$veritasscripts/step_2.sh

# read proposal id from enfidentity.proposal_id
enfidentityproposal_id=$(cat $qadenaproviderscripts/proposals/enfidentitysrvprv.proposal_id)
enfdsvsproposal_id=$(cat $qadenaproviderscripts/proposals/enfdsvssrvprv.proposal_id)

$qadenatestscripts/gov_deposit_from_treasury.sh $enfidentityproposal_id 10000000qdn
$qadenatestscripts/gov_vote_from_treasury.sh $enfidentityproposal_id yes

$qadenatestscripts/gov_deposit_from_treasury.sh $enfdsvsproposal_id 10000000qdn
$qadenatestscripts/gov_vote_from_treasury.sh $enfdsvsproposal_id yes

$qadenaproviderscripts/query_service_provider_proposal.sh $enfidentityproposal_id --wait

$qadenaproviderscripts/query_service_provider_proposal.sh $enfdsvsproposal_id --wait

$veritasscripts/step_3.sh

echo "These go into env-enf-dev"

# echo the contents of each of the names and keys
echo "SEC_DSVS_EPH_USERNAME='`cat $dsvsname-names.base64`'"
echo "SEC_DSVS_EPH_PRIVATE_KEY='`cat $dsvsname-keys.base64`'"

echo ""

echo "SEC_DSVS_EPH_CREDENTIAL_USERNAME='`cat $dsvsname-credential-names.base64`'"
echo "SEC_DSVS_EPH_CREDENTIAL_PRIVATE_KEY='`cat $dsvsname-credential-keys.base64`'"

echo ""

# SEC_DSVS_SRV_PRV_USERNAME
echo "SEC_DSVS_SRV_PRV_USERNAME='`cat $dsvsprovidername-names.base64`'"
# SEC_DSVS_SRV_PRV_PRIVATE_KEY
echo "SEC_DSVS_SRV_PRV_PRIVATE_KEY='`cat $dsvsprovidername-keys.base64`'"

echo ""

# SEC_IDENTITY_SRV_PRV_USERNAME
echo "SEC_IDENTITY_SRV_PRV_USERNAME='`cat $identityprovidername-names.base64`'"
# SEC_IDENTITY_SRV_PRV_PRIVATE_KEY
echo "SEC_IDENTITY_SRV_PRV_PRIVATE_KEY='`cat $identityprovidername-keys.base64`'"

echo ""

#SEC_CREATE_WALLET_SPONSOR_USERNAME
echo "SEC_CREATE_WALLET_SPONSOR_USERNAME='`cat $createwalletsponsorname-names.base64`'"
# SEC_CREATE_WALLET_SPONSOR_PRIVATE_KEY
echo "SEC_CREATE_WALLET_SPONSOR_PRIVATE_KEY='`cat $createwalletsponsorname-keys.base64`'"

echo ""

# REUSABLE_EKYC_APP_NAME
echo "REUSABLE_EKYC_APP_NAME='`cat $ekycphidentityprovidername-names.base64`'"
echo "REUSABLE_EKYC_APP_PRIVATE_KEY='`cat $ekycphidentityprovidername-keys.base64`'"
