#!/bin/zsh

set -e

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

# inputs

ekycphtreasurymnemonic="vendor property such denial jeans fog gaze cushion simple destroy front engine dragon crisp baby evoke disorder ladder wear palm aunt muscle deer claim"
signermnemonic="sad denial auto lawsuit resemble valve method oil eager kid bleak security wife give conduct forest nurse fossil tired tenant capital wine renew idle"
createwalletsponsormnemonic="situate chase law sure moon cute another possible script catch chaos zoo web midnight shoot regular comic myth surprise draft battle know question oil"
identityprovidermnemonic="ten input amount super napkin lend job surface chase garlic observe warm soap abstract jeans sting chat priority brave mansion bracket spin evoke despair"
dsvsprovidermnemonic="verb next spot entry congress electric fiction admit manage speed depart muscle any move adapt color portion cabin play bag eye upper couch vessel"

provideramount="100000qdn"
signeramount="100000qdn"
createwalletsponsoramount="100000qdn"


pioneer="pioneer1"

treasuryname="ekycph-treasury"
identityprovidername="ekycphidentitysrvprv"
dsvsprovidername="ekycphdsvssrvprv"
dsvsname="ekycphdsvs"
createwalletsponsorname="ekycph-create-wallet-sponsor"
email="no-repy@ekyc.ph"
avalue="2000"
firstname="EKYCPH"

birthdate="2025-Jan-01"
phone="+6320000000"



#
count=2

echo "-------------------------"
echo "Staking from treasury to pioneer1"
echo "-------------------------"

# need to stake from treasury to pioneer1, do this only once
$qadenatestscripts/gov_stake_from_treasury.sh pioneer1 10000000qdn


$veritasscripts/step_1.sh --count $count --provideramount $provideramount --signeramount $signeramount --createwalletsponsoramount $createwalletsponsoramount --createwalletsponsorname $createwalletsponsorname --pioneer $pioneer --treasurymnemonic $ekycphtreasurymnemonic --signermnemonic $signermnemonic --createwalletsponsormnemonic $createwalletsponsormnemonic --identityprovidermnemonic $identityprovidermnemonic --dsvsprovidermnemonic $dsvsprovidermnemonic --treasuryname $treasuryname --identityprovidername $identityprovidername --dsvsprovidername $dsvsprovidername --email $email --avalue $avalue --firstname $firstname --birthdate $birthdate --phone $phone --dsvsname $dsvsname


# grants 2M qdn from "treasury" to "ekycph-treasury"
echo "-------------------------"
echo "Granting 2M qdn from treasury to ekycph-treasury"
echo "-------------------------"
$qadenatestscripts/grant_from_treasury.sh $treasuryname 2000000qdn

$veritasscripts/step_2.sh

# read proposal id from ekycphidentity.proposal_id
ekycphidentityproposal_id=$(cat $qadenaproviderscripts/proposals/ekycphidentitysrvprv.proposal_id)
ekycphdsvsproposal_id=$(cat $qadenaproviderscripts/proposals/ekycphdsvssrvprv.proposal_id)

$qadenatestscripts/gov_deposit_from_treasury.sh $ekycphidentityproposal_id 10000000qdn
$qadenatestscripts/gov_vote_from_treasury.sh $ekycphidentityproposal_id yes

$qadenatestscripts/gov_deposit_from_treasury.sh $ekycphdsvsproposal_id 10000000qdn
$qadenatestscripts/gov_vote_from_treasury.sh $ekycphdsvsproposal_id yes

$qadenaproviderscripts/query_service_provider_proposal.sh $ekycphidentityproposal_id --wait

$qadenaproviderscripts/query_service_provider_proposal.sh $ekycphdsvsproposal_id --wait

$veritasscripts/step_3.sh
