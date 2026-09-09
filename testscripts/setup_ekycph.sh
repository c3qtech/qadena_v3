#!/bin/zsh

set -e

# get script dir
SCRIPT_DIR="${0:A:h}"

# NO KEYRING BACKEND IS SET HERE, DELIBERATELY.
#
# This used to force `test`, because the harness is unattended and cannot answer a passphrase
# prompt.  That was right while every chain was built with an unencrypted keyring.  config.yml now
# asks for keyring-backend: file, and init.sh migrates the keys there and deletes keyring-test -- so
# on a freshly built chain `treasury` and the pioneer are ENCRYPTED, and forcing `test` made every
# funding step fail with "key not found".
#
# Setting it here at all -- even with := -- pre-empts the answer: scripts/setup_env.sh reads the
# node's own client.toml, and a value already in the environment stops it looking.  So leave it
# unset and let that detection run.  An explicit export by the caller still wins, which is how
# deployment_full_setup.sh supplies the passphrase alongside it.

source "$SCRIPT_DIR/../scripts/setup_env.sh"

# inputs

ekycphtreasurymnemonic="vendor property such denial jeans fog gaze cushion simple destroy front engine dragon crisp baby evoke disorder ladder wear palm aunt muscle deer claim"
signermnemonic="sad denial auto lawsuit resemble valve method oil eager kid bleak security wife give conduct forest nurse fossil tired tenant capital wine renew idle"
createwalletsponsormnemonic="situate chase law sure moon cute another possible script catch chaos zoo web midnight shoot regular comic myth surprise draft battle know question oil"
identityprovidermnemonic="ten input amount super napkin lend job surface chase garlic observe warm soap abstract jeans sting chat priority brave mansion bracket spin evoke despair"
dsvsprovidermnemonic="verb next spot entry congress electric fiction admit manage speed depart muscle any move adapt color portion cabin play bag eye upper couch vessel"


config_yml_treasurymnemonic="eyebrow unaware jealous actor annual farm radio open sword memory other secret twelve reduce festival buddy peace fun film return sniff december february post"

# check if "treasury" key exists by "qadenad "
if qadenad_alias keys show treasury > /dev/null 2>&1; then
    echo "treasury key already exists"
else
    echo "treasury key not found, adding it now"
    # MNEMONIC FIRST, THEN THE PASSPHRASE, down one pipe: `keys add --recover` reads them in that
    # order and qadenad_alias would replace stdin with its own passphrase feed, so the mnemonic
    # would never arrive.  _raw feeds nothing, leaving the ordering to the call site.
    { echo "$config_yml_treasurymnemonic"
      [ -z "${QADENA_KEYRING_PASS:-}" ] || { echo "$QADENA_KEYRING_PASS"; echo "$QADENA_KEYRING_PASS"; }
    } | qadenad_alias_raw keys add treasury --recover
fi


provideramount="100000qdn"
signeramount="100000qdn"
createwalletsponsoramount="100000qdn"

# What each foundation account is seeded with.  Sized well above the amounts above because these
# accounts pay FEES for many wallets rather than endowing a few, and credential issuance is by far
# the most expensive operation (~5.9e19 aqdn against ~3.2e14 for a document signature).
foundationamount="2000000qdn"

# THE SAME TWO DEVNET FOUNDATION ACCOUNTS setup_veritas.sh uses, ON PURPOSE.
#
# In production each programme gets its own pair -- foundation_scripts/deployment_profile.sh maps
# ekycph to foundation-ekycph-appsvr/-users -- because the keyring has no namespaces and bucket 10
# funds more than one programme.  On the devnet there is ONE foundation, one keyring and one chain,
# and all three harnesses (veritas, ekycph, enf) run against it in sequence.  Sharing the pair here
# means no new mnemonics have to be invented and committed to a public repo, and it costs nothing:
# authz and feegrant are keyed on (granter, grantee), so three deployments granting from one
# granter to three disjoint sets of grantees do not overwrite each other.
#
# The addresses are therefore the ones already baked into the dev env files:
#   foundation-users  qadena1j75rmpk86n2ln27p9c42qa2qkw4zy4zkgrzpjm
#   foundation-appsvr qadena13vvrf5879hfgrv3krucpkpgmph549gnzv923vq
# setup_veritas.sh holds their fixed mnemonics and recovers them; this harness only uses them, so
# run that one first on a fresh chain, or pass --fund-mode banksend.
foundation_appsvr="foundation-appsvr"
foundation_users="foundation-users"

# foundation-sponsored (default) or banksend (the original).  See the funding block below.
fund_mode="foundation-sponsored"


# The DEVNET\'s genesis validator is `pioneer1`; a launch chain names its own


# (qfi-pioneer1).  Env default so a whole suite run can be pointed at either without


# editing eight scripts; --pioneer still wins where this script takes one.


pioneer="${QADENA_PIONEER:-pioneer1}"
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
            echo "Usage: $0 [--pioneer <pioneer>] [--fund-mode foundation-sponsored|banksend]"
            echo ""
            echo "  --fund-mode foundation-sponsored  (default) the foundation pays by fee grant;"
            echo "                       ekycph holds no tokens and gets its own admin key, its own"
            echo "                       ~/sec-ekycph state and its own sponsor pool.  Mirrors the"
            echo "                       production flow in foundation_scripts/ekycph_*.sh."
            echo "  --fund-mode banksend  the original: 2M qdn into ekycph-treasury plus an AML"
            echo "                       whitelist exemption.  Kept for a deployment mid-migration."
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--pioneer <pioneer>] [--fund-mode foundation-sponsored|banksend]"
            exit 1
            ;;
    esac
done





#
count=2

echo "-------------------------"
echo "Staking from treasury to $pioneer"
echo "-------------------------"

# need to stake from treasury to pioneer1, do this only once
$qadenatestscripts/gov_stake_from_treasury.sh $pioneer 10000000qdn


# --deployment IS PASSED ONLY IN SPONSORED MODE, and that is deliberate.
#
# It gives ekycph its own admin key (ekycph-admin) and its own state directory (~/sec-ekycph) out of
# foundation_scripts/deployment_profile.sh.  Both are REQUIRED here and not merely tidy: sponsored
# mode is the only mode that creates an admin key, and without --deployment step_1 would name it
# sec-veritas-admin -- the same key setup_veritas.sh creates, in the same keyring, on the same
# devnet.  The second harness to run would silently adopt the first one's admin identity.
#
# banksend keeps EXACTLY its previous invocation, down to the shared ~/sec-veritas state directory.
# It creates no admin key so it cannot collide, it is the legacy path, and a working legacy path is
# worth more than consistency with a mode it does not use.
# A TYPO MUST NOT MEAN "SPONSORED".  Every branch below is `if banksend ... else sponsored`, so
# --fund-mode banksned would run the sponsored path -- creating an admin key and a sponsor pool for
# an operator who asked for the opposite.  Checked once, here, before anything is written.
case "$fund_mode" in
    foundation-sponsored|banksend) ;;
    *) echo "unknown --fund-mode '$fund_mode' (foundation-sponsored | banksend)"; exit 1 ;;
esac

# THE SPONSOR ACCOUNTS MUST EXIST *BEFORE* step_1, NOT AFTER.
#
# step_1 in sponsored mode requires the two foundation sponsor ADDRESSES (--appsvr/--users): it
# writes them into variables.json and derives every pre-grant from them, so it refuses to start
# without them.  This block used to sit AFTER the step_1 call -- the order setup_veritas.sh still
# had -- which meant a sponsored run died on
#
#     sponsored mode needs the foundation sponsor's ADDRESS
#
# before anything was created.  testscripts/veritas_full_setup.sh never hit it because the fleet
# path resolves the addresses from the multisig prepare stage and passes them explicitly.
step1_extra=()
step23_extra=()
if [ "$fund_mode" != "banksend" ]; then
    echo "-------------------------"
    echo "Toll-free: funding two foundation accounts, no $treasuryname"
    echo "-------------------------"
    # ONE SCRIPT OWNS THESE TWO ACCOUNTS.  It recovers them from their fixed dev mnemonics and tops
    # up the funding, idempotently, so calling it here costs one bank send per account on a re-run.
    # Doing it this way rather than requiring setup_veritas.sh to have run first matters: ekycph
    # does not otherwise depend on VERITAS in any way, and making a 30-wallet bring-up a
    # prerequisite for two keys and a transfer is a prerequisite nobody would guess.
    $qadenatestscripts/setup_foundation_accounts.sh \
        --appsvr "$foundation_appsvr" --users "$foundation_users" --amount "$foundationamount"

    _appsvr_addr=$(qadenad_alias keys show "$foundation_appsvr" -a 2>/dev/null)
    _users_addr=$(qadenad_alias keys show "$foundation_users" -a 2>/dev/null)
    [ -n "$_appsvr_addr" ] && [ -n "$_users_addr" ] \
        || { echo "FAILED: could not resolve the foundation sponsor addresses"; exit 1; }
    echo "  appsvr $_appsvr_addr"
    echo "  users  $_users_addr"

    # NOTE: no whitelist_bank_send.sh here, deliberately.  The exemption existed only because a
    # treasury making direct transfers looks exactly like the pattern the AML scanner is there to
    # catch.  Fee grants are not bank sends, so the hole is not needed and is not opened.
    export VERITAS_FUND_MODE=foundation-sponsored
    export VERITAS_FOUNDATION_APPSVR="$foundation_appsvr"

    step1_extra=(--deployment ekycph --appsvr "$_appsvr_addr" --users "$_users_addr")
    step23_extra=(--deployment ekycph)
fi
$veritasscripts/step_1.sh "${step1_extra[@]}" --count $count --provideramount $provideramount --signeramount $signeramount --createwalletsponsoramount $createwalletsponsoramount --createwalletsponsorname $createwalletsponsorname --pioneer $pioneer --treasurymnemonic $ekycphtreasurymnemonic --signermnemonic $signermnemonic --createwalletsponsormnemonic $createwalletsponsormnemonic --identityprovidermnemonic $identityprovidermnemonic --dsvsprovidermnemonic $dsvsprovidermnemonic --treasuryname $treasuryname --identityprovidername $identityprovidername --dsvsprovidername $dsvsprovidername --email $email --avalue $avalue --firstname $firstname --birthdate $birthdate --phone $phone --dsvsname $dsvsname


# FUNDING.  Two shapes, selected by $fund_mode -- the same two setup_veritas.sh offers.
#
# foundation-sponsored (default) -- NO ekycph TREASURY AT ALL.  The foundation pays by fee grant and
#   ekycph holds no tokens.  Two foundation accounts rather than one, because the populations behave
#   differently:
#
#     foundation-appsvr  ekycph's own operational wallets.  A FIXED set, known at deployment, so
#                        they are granted directly, once, here.  No key of ekycph's can spend the
#                        foundation's money -- only present these grants.
#     foundation-users   citizen wallets.  These appear continuously, so the app-server issues their
#                        grants at runtime via authz.  That delegation is unbounded by nature, and
#                        keeping it on a separate account confines it to the user float.
#
# banksend -- the original: 2M qdn into ekycph-treasury, an AML whitelist exemption so that treasury
#   can make direct bank sends at all, and a fan-out of one transfer per wallet.
if [ "$fund_mode" = "banksend" ]; then
    # grants 2M qdn from "treasury" to "ekycph-treasury"
    echo "-------------------------"
    echo "Granting 2M qdn from treasury to ekycph-treasury"
    echo "-------------------------"
    $qadenatestscripts/grant_from_treasury.sh $treasuryname 2000000qdn

    # step_3.sh funds providers and users with `tx bank send` FROM $treasuryname.  Those sends are
    # AML-scanned like any other, and a treasury is not a wallet, so without an exemption every one
    # of them is refused.  Must land before step_3.sh runs.
    echo "-------------------------"
    echo "Whitelisting $treasuryname for direct bank sends"
    echo "-------------------------"
    $qadenatestscripts/whitelist_bank_send.sh $treasuryname \
        "ekycph deployment treasury: funds providers and users by direct bank send"
fi

# ---------------------------------------------------------------------------------------------
# THE FOUNDATION'S FIRST ACTION -- between step_1 and step_2, and it cannot be skipped.
#
# In sponsored mode every wallet step_2 creates is paid for by a FEE GRANT the foundation issued
# against it in advance.  Without this, create-wallet fails with
#
#     rpc error: ... fee-grant not found: not found
#
# which reads like a chain problem and is in fact a missing step.  step_1 emits the pre-grant block
# for exactly this; on a real deployment a human carries it to QFI, and here the harness plays both
# roles.  --foundation-appsvr overrides the profile's production name with the shared devnet one.
if [ "$fund_mode" != "banksend" ]; then
    echo "-------------------------"
    echo "FOUNDATION: delegate grant authority and pre-grant every wallet"
    echo "-------------------------"
    # step_1 wrote this into the deployment's state directory -- the profile's DEPLOY_SEC_HOME,
    # which --deployment ekycph selected, unless the caller pointed VERITAS_SEC_HOME elsewhere.
    _pregrant="${VERITAS_SEC_HOME:-$HOME/sec-ekycph}/pregrant_addresses.json"
    [ -r "$_pregrant" ] || { echo "FAILED: no $_pregrant -- step_1 did not complete"; exit 1; }
    $qadenafoundationscripts/ekycph_after_step_1.sh --pregrant "$_pregrant" \
        --foundation-appsvr "$foundation_appsvr"
fi

$veritasscripts/step_2.sh "${step23_extra[@]}"

# read proposal id from ekycphidentity.proposal_id
ekycphidentityproposal_id=$(cat $qadenaproviderscripts/proposals/ekycphidentitysrvprv.proposal_id)
ekycphdsvsproposal_id=$(cat $qadenaproviderscripts/proposals/ekycphdsvssrvprv.proposal_id)

# DO NOT VOTE ON A PROPOSAL THAT REGISTERS SOMETHING ALREADY REGISTERED.
#
# setup_provider_base.sh submits a provider proposal every run, so a SECOND run of this harness
# against a chain where the providers already exist produces a duplicate.  It passes the vote and
# then FAILS on execution -- "what it registers already exists" -- and the wait below used to spin
# on it forever.  Measured on qadena_4828-1, 2026-09-09: a re-run of a green deployment.
#
# The chain is the authority, not the .proposal_id file: that file is overwritten every run and
# says nothing about whether the provider is registered.
_registered() {
    qadenad_alias query qadena list-interval-public-key-id --output json 2>/dev/null \
        | sed -n '/^{/,$p' \
        | jq -r --arg n "$1" '(.intervalPublicKeyID // [])[] | select(.nodeID==$n) | .pubKID' 2>/dev/null | head -1
}

for _spec in "ekycphidentitysrvprv:$ekycphidentityproposal_id" "ekycphdsvssrvprv:$ekycphdsvsproposal_id"; do
    _name="${_spec%%:*}"; _pid="${_spec#*:}"
    if [ -n "$(_registered "$_name")" ]; then
        echo "$_name already registered on chain -- skipping proposal $_pid"
        continue
    fi
    $qadenatestscripts/gov_deposit_from_treasury.sh $_pid 10000000qdn
    $qadenatestscripts/gov_vote_from_treasury.sh $_pid yes
    $qadenaproviderscripts/query_service_provider_proposal.sh $_pid --wait
done

$veritasscripts/step_3.sh "${step23_extra[@]}"

# ---------------------------------------------------------------------------------------------
# STEP 4 -- the FOUNDATION's final action.
#
# In foundation_scripts/ekycph_after_step_3.sh rather than inlined, because in a real deployment
# this is NOT ekycph's to run: every grant it issues is signed by the foundation, and authz cannot
# be sub-delegated, so ekycph could not do it even with the step_1 authorisation.  This harness
# calls it because it plays both roles and holds every key in one keyring -- which is exactly why
# it cannot tell the difference and the split has to be enforced by where the code lives.
#
# --foundation-users/-appsvr override the profile's production names with the shared devnet pair.
if [ "$fund_mode" != "banksend" ]; then
    # --pool-addresses, NOT --count.  With --count this DERIVES the pool wallet names and resolves
    # each in the coordinator keyring, which on a devnet defaults to the NODE's home -- but the
    # deployment's keys live in ~/sec-ekycph.  Every lookup missed and it reported
    #     SKIPPED ekycph-create-wallet-sponsor -- not resolvable in ~/qadena
    #     authorised 0 wallet(s); 3 incomplete
    # while exiting 0, so only the verifier caught it.  step_3 already wrote the ADDRESSES; passing
    # them needs no keyring at all.
    _pool="${VERITAS_SEC_HOME:-$HOME/sec-ekycph}/pool_addresses.json"
    [ -r "$_pool" ] || { echo "FAILED: no $_pool -- step_3 did not complete"; exit 1; }
    $qadenafoundationscripts/ekycph_after_step_3.sh --pool-addresses "$_pool" \
        --foundation-users "$foundation_users" \
        --foundation-appsvr "$foundation_appsvr"
fi

echo "These go into env-ekycph-dev"

# echo the contents of each of the names and keys
echo "SEC_DSVS_EPH_USERNAME='`cat $dsvsname-names.base64`'"
echo "SEC_DSVS_EPH_PRIVATE_KEY='`cat $dsvsname-keys.base64`'"

echo "SEC_DSVS_EPH_CREDENTIAL_USERNAME='`cat $dsvsname-credential-names.base64`'"
echo "SEC_DSVS_EPH_CREDENTIAL_PRIVATE_KEY='`cat $dsvsname-credential-keys.base64`'"

# SEC_DSVS_SRV_PRV_USERNAME
echo "SEC_DSVS_SRV_PRV_USERNAME='`cat $dsvsprovidername-names.base64`'"
# SEC_DSVS_SRV_PRV_PRIVATE_KEY
echo "SEC_DSVS_SRV_PRV_PRIVATE_KEY='`cat $dsvsprovidername-keys.base64`'"

# SEC_IDENTITY_SRV_PRV_USERNAME
echo "SEC_IDENTITY_SRV_PRV_USERNAME='`cat $identityprovidername-names.base64`'"
# SEC_IDENTITY_SRV_PRV_PRIVATE_KEY
echo "SEC_IDENTITY_SRV_PRV_PRIVATE_KEY='`cat $identityprovidername-keys.base64`'"

#SEC_CREATE_WALLET_SPONSOR_USERNAME
echo "SEC_CREATE_WALLET_SPONSOR_USERNAME='`cat $createwalletsponsorname-names.base64`'"
# SEC_CREATE_WALLET_SPONSOR_PRIVATE_KEY
echo "SEC_CREATE_WALLET_SPONSOR_PRIVATE_KEY='`cat $createwalletsponsorname-keys.base64`'"

