#!/bin/zsh

set -e

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

# inputs

sectreasurymnemonic="head recall pear surface flavor inquiry aspect pause snow scheme planet million weapon outdoor text effort enjoy school round expand deposit wave drift reopen"
signermnemonic="tide ugly fork short cushion girl earth stage anger away pig screen blood frequent link become crowd visa end present share helmet brain fit"
createwalletsponsormnemonic="barely true danger guilt recipe idle name any blind toast identify mango pilot fork safe clown reveal chalk artefact genuine debate early home concert"
identityprovidermnemonic="canoe oppose eternal occur film common dirt tomorrow lottery fun mask quote result account nasty tuna seat miracle have idle trophy frog catalog kiss"
dsvsprovidermnemonic="angry addict suit reform ostrich ride icon cushion park yellow wisdom mobile column sweet use anchor since tragic series ladder asthma dose prosper voice"

provideramount="100000qdn"
signeramount="100000qdn"
createwalletsponsoramount="100000qdn"

pioneer="pioneer1"

# count = 30
count=2

echo "-------------------------"
echo "Staking from treasury to pioneer1"
echo "-------------------------"

# need to stake from treasury to pioneer1, do this only once
$qadenatestscripts/gov_stake_from_treasury.sh pioneer1 10000000qdn


$veritasscripts/step_1.sh --count $count --provideramount $provideramount --signeramount $signeramount --createwalletsponsoramount $createwalletsponsoramount --pioneer $pioneer --sectreasurymnemonic $sectreasurymnemonic --signermnemonic $signermnemonic --createwalletsponsormnemonic $createwalletsponsormnemonic --identityprovidermnemonic $identityprovidermnemonic --dsvsprovidermnemonic $dsvsprovidermnemonic

# grants 1M qdn from "treasury" to "sec-treasury"
echo "-------------------------"
echo "Granting 1M qdn from treasury to sec-treasury"
echo "-------------------------"
$qadenatestscripts/grant_from_treasury.sh sec-treasury 1000000qdn

$veritasscripts/step_2.sh

# read proposal id from secidentity.proposal_id
secidentityproposal_id=$(cat $qadenaproviderscripts/proposals/secidentitysrvprv.proposal_id)
secdsvsproposal_id=$(cat $qadenaproviderscripts/proposals/secdsvssrvprv.proposal_id)

$qadenatestscripts/gov_deposit_from_treasury.sh $secidentityproposal_id 10000000qdn
$qadenatestscripts/gov_vote_from_treasury.sh $secidentityproposal_id yes

$qadenatestscripts/gov_deposit_from_treasury.sh $secdsvsproposal_id 10000000qdn
$qadenatestscripts/gov_vote_from_treasury.sh $secdsvsproposal_id yes

$qadenaproviderscripts/query_service_provider_proposal.sh $secidentityproposal_id --wait

$qadenaproviderscripts/query_service_provider_proposal.sh $secdsvsproposal_id --wait

$veritasscripts/step_3.sh
