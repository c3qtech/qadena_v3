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

# What each foundation account is seeded with.  Sized well above the amounts above because these
# accounts pay FEES for many wallets rather than endowing a few, and credential issuance is by far
# the most expensive operation (measured at ~5.9e19 aqdn against ~3.2e14 for a document signature).
foundationamount="2000000qdn"
foundation_appsvr="foundation-appsvr"
foundation_users="foundation-users"

# FIXED MNEMONICS so the two foundation addresses are the SAME on every re-init, the way the SEC
# mnemonics above already are. Without this each init produced fresh random accounts and the two
# addresses had to be copied by hand into .env after every rebuild.
#
#   foundation-users  qadena1j75rmpk86n2ln27p9c42qa2qkw4zy4zkgrzpjm
#   foundation-appsvr qadena13vvrf5879hfgrv3krucpkpgmph549gnzv923vq
#
# TEST KEYS ONLY. They are in a public repo, so anyone can spend from them. A real deployment's
# foundation accounts belong to the Qadena Foundation and their addresses go into the production and
# staging SSM parameters instead -- never these. The addresses above are safe to bake into the dev
# env files precisely because the money behind them is worthless.
foundationusersmnemonic="airport south group aerobic august arm source candy tilt damp stage fork mention clerk plunge garbage nut blood fall flight indoor season broken fog"
foundationappsvrmnemonic="angle unknown bean lunch base vague awful together dismiss swallow climb common upgrade jelly machine plunge paper vote maple frog junk brisk bind weekend"

# feegrant (no SEC treasury) or banksend (the original).  See the funding block below.
fund_mode="feegrant"

# The DEVNET\'s genesis validator is `pioneer1`; a launch chain names its own

# (qfi-pioneer1).  Env default so a whole suite run can be pointed at either without

# editing eight scripts; --pioneer still wins where this script takes one.

pioneer="${QADENA_PIONEER:-pioneer1}"
# accept 1 parameter, the pioneer name
# accept named parameters to override all these mnemonics
# Process command line arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --pioneer)
            pioneer="$2"
            shift 2
            ;;
        --fund-mode)
            fund_mode="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [--pioneer <pioneer>] [--fund-mode feegrant|banksend]"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--pioneer <pioneer>] [--fund-mode feegrant|banksend]"
            exit 1
            ;;
    esac
done

#
count=30

echo "-------------------------"
echo "Staking from treasury to $pioneer"
echo "-------------------------"

# need to stake from treasury to pioneer1, do this only once
$qadenatestscripts/gov_stake_from_treasury.sh $pioneer 10000000qdn


$veritasscripts/step_1.sh --count $count --provideramount $provideramount --signeramount $signeramount --createwalletsponsoramount $createwalletsponsoramount --pioneer $pioneer --treasurymnemonic $sectreasurymnemonic --signermnemonic $signermnemonic --createwalletsponsormnemonic $createwalletsponsormnemonic --identityprovidermnemonic $identityprovidermnemonic --dsvsprovidermnemonic $dsvsprovidermnemonic

# FUNDING.  Two shapes, selected by $fund_mode.
#
# feegrant (default) -- NO SEC TREASURY AT ALL.  The Qadena foundation pays, by fee grant, and SEC
#   holds no tokens.  Two foundation accounts rather than one, because the two populations behave
#   differently and separating them is worth more than the extra account:
#
#     foundation-appsvr  SEC's own operational wallets.  A FIXED set, known at deployment, so they
#                        are granted directly, once, here.  No delegation and no key of SEC's can
#                        spend the foundation's money -- only present these grants.
#     foundation-users   citizen wallets.  These appear continuously (every onboarding, QR scan and
#                        key rotation mints one), so the app-server issues their grants at runtime
#                        via authz.  That delegation is unbounded by nature, and keeping it on a
#                        separate account confines it to the user float.
#
#   It also makes usage independently observable: appsvr burn tracks SEC's processing, users burn
#   tracks citizen activity, and a divergence between them is a real anomaly signal.
#
# banksend -- the original: 2M qdn moved into a sec-treasury, an AML whitelist exemption so that
#   treasury can make direct bank sends at all, and a fan-out of one transfer per wallet.  Kept
#   because a deployment mid-migration may still need it.
if [ "$fund_mode" = "banksend" ]; then
    echo "-------------------------"
    echo "Granting 2M qdn from treasury to sec-treasury"
    echo "-------------------------"
    $qadenatestscripts/grant_from_treasury.sh sec-treasury 2000000qdn

    # Those sends are AML-scanned like any other, and a treasury is not a wallet, so without an
    # exemption every one of them is refused.  Must land before step_3.sh runs.
    echo "-------------------------"
    echo "Whitelisting sec-treasury for direct bank sends"
    echo "-------------------------"
    $qadenatestscripts/whitelist_bank_send.sh sec-treasury \
        "veritas deployment treasury: funds providers and users by direct bank send"
else
    echo "-------------------------"
    echo "Toll-free: funding two foundation accounts, no sec-treasury"
    echo "-------------------------"
    for f in "$foundation_appsvr" "$foundation_users"; do
        if qadenad_alias keys show "$f" > /dev/null 2>&1; then
            echo "$f already exists"
        else
            echo "recovering $f from its fixed mnemonic"
            if [ "$f" = "$foundation_users" ]; then mn="$foundationusersmnemonic"; else mn="$foundationappsvrmnemonic"; fi
            echo "$mn" | qadenad_alias keys add "$f" --recover --algo eth_secp256k1 > /dev/null 2>&1
        fi
        $qadenatestscripts/grant_from_treasury.sh "$f" "$foundationamount"
    done
    # NOTE: no whitelist_bank_send.sh here, deliberately.  The exemption existed only because a
    # treasury making direct transfers looks exactly like the pattern the AML scanner is there to
    # catch.  Fee grants are not bank sends, so the hole is not needed and is not opened.
    export VERITAS_FUND_MODE=feegrant
    export VERITAS_FOUNDATION_APPSVR="$foundation_appsvr"
fi

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


# ---------------------------------------------------------------------------------------------
# STEP 4 -- the FOUNDATION's final action.
#
# Extracted into veritas_scripts/step_4.sh rather than inlined, because in a real deployment this is
# NOT SEC's to run: every grant it issues is signed by the foundation, and authz cannot be
# sub-delegated, so SEC could not do it even with the step_1 authorisation. Inlining it here would
# have hidden that -- this harness holds every key in one keyring and so cannot tell the difference.
#
# The harness calls it because it plays both roles; SEC's real procedure stops after step_3 and waits
# for the foundation to run this and return the two addresses.
if [ "$fund_mode" != "banksend" ]; then
    $veritasscripts/step_4.sh --foundation-users "$foundation_users" \
        --foundation-appsvr "$foundation_appsvr" --count "$count"
fi
