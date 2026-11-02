#!/bin/zsh

set -e

# get script dir
SCRIPT_DIR="${0:A:h}"

# The keyring backend is left unset here.  scripts/setup_env.sh reads it from the node's
# client.toml; a value already in the environment stops it looking.  An explicit export by the
# caller wins.

source "$SCRIPT_DIR/../scripts/setup_env.sh"
# EXPORT THE RESOLVED BACKEND. setup_env.sh reads it from client.toml (`file` on a current devnet)
# but does not export it, and setup_foundation_accounts.sh forces `test` when it sees it unset --
# so, called from here, it looked in an empty test keyring, "recovered" foundation-appsvr into a
# new unencrypted keyring-test, and failed with "treasury.info: key not found".
export QADENA_KEYRING_BACKEND

# THE DEPLOYMENT PROFILE.  Sourced AFTER setup_env.sh, which clobbers SCRIPT_DIR, so re-derive the
# path from $0 rather than trusting the variable to still point here.
# DEV STATE, KEPT APART FROM FLEET STATE.  Every key this script makes derives from the
# hardcoded public mnemonics above, so its deployment home is throwaway material that must not
# share a parent with a real fleet's keyring and sealed mnemonics -- ~/qadena-launch holds both
# c3q-mainnet's custody directories and the fleet launch dirs.  The profile builds
# DEPLOY_SEC_HOME under $QADENA_LAUNCH_ROOT, so setting it here is the whole change.
# EXPORTED, because step_1/2/3 and the after_step_* scripts are CHILD PROCESSES that load the
# profile themselves -- an unexported value would put the parent and the children in different
# directories, which is precisely the split that reported a successful step_1 as a failure.
# An explicit QADENA_LAUNCH_ROOT from the caller still wins, as does VERITAS_SEC_HOME.
export QADENA_LAUNCH_ROOT="${QADENA_LAUNCH_ROOT:-$HOME/qadena-dev-launch}"

source "${0:A:h}/../foundation_scripts/deployment_profile.sh"
deployment_profile_load "ekycph" || exit 1
# THE DEPLOYMENT HOME, FROM THE PROFILE -- NEVER A LITERAL.  step_1 defaults
# VERITAS_SEC_HOME to $DEPLOY_SEC_HOME and writes pregrant_addresses.json and
# pool_addresses.json there; it is a child process, so the value does not come back.  The two
# checks below used a hardcoded "$HOME/ekyc-ph", which the profile moved to
# "$QADENA_LAUNCH_ROOT/ekyc-ph" -- so a perfectly successful step_1 was reported as
# "step_1 did not complete".  Read it from the same place step_1 does.
ekycph_home="${VERITAS_SEC_HOME:-$DEPLOY_SEC_HOME}"

# inputs

ekycphtreasurymnemonic="vendor property such denial jeans fog gaze cushion simple destroy front engine dragon crisp baby evoke disorder ladder wear palm aunt muscle deer claim"
signermnemonic="sad denial auto lawsuit resemble valve method oil eager kid bleak security wife give conduct forest nurse fossil tired tenant capital wine renew idle"
createwalletsponsormnemonic="situate chase law sure moon cute another possible script catch chaos zoo web midnight shoot regular comic myth surprise draft battle know question oil"
identityprovidermnemonic="ten input amount super napkin lend job surface chase garlic observe warm soap abstract jeans sting chat priority brave mansion bracket spin evoke despair"
dsvsprovidermnemonic="verb next spot entry congress electric fiction admit manage speed depart muscle any move adapt color portion cabin play bag eye upper couch vessel"


config_yml_treasurymnemonic="eyebrow unaware jealous actor annual farm radio open sword memory other secret twelve reduce festival buddy peace fun film return sniff december february post"


provideramount="100000qdn"
signeramount="100000qdn"
createwalletsponsoramount="100000qdn"

# What each foundation account is seeded with.  Sized well above the amounts above because these
# accounts pay FEES for many wallets rather than endowing a few, and credential issuance is by far
# the most expensive operation (~5.9e19 aqdn against ~3.2e14 for a document signature).
foundationamount="2000000qdn"

# The two devnet foundation accounts, shared with setup_veritas.sh and setup_enf.sh.  authz and
# feegrant are keyed on (granter, grantee), so deployments sharing a granter do not collide.
# In production each programme has its own pair -- see foundation_scripts/deployment_profile.sh.
#
#   foundation-users  qadena1j75rmpk86n2ln27p9c42qa2qkw4zy4zkgrzpjm
#   foundation-appsvr qadena13vvrf5879hfgrv3krucpkpgmph549gnzv923vq
#
# testscripts/setup_foundation_accounts.sh creates and funds them.
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
# IDENTITY FROM THE PROFILE.  These were literals here AND (as SEC values) in step_1.sh, so the
# devnet path and the fleet path disagreed about who ekycph is -- the fleet path minted SEC's
# credentials and collided.  One source now; step_1.sh defaults from the same place, so passing
# them below is belt-and-braces rather than the only thing setting them.
# (The email also read "no-repy@" here -- a typo that went into a real credential.)
email="$DEPLOY_EMAIL"
avalue="$DEPLOY_AVALUE"
firstname="$DEPLOY_FIRSTNAME"
birthdate="$DEPLOY_BIRTHDATE"
phone="$DEPLOY_PHONE"

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
            echo "                       ~/ekyc-ph state and its own sponsor pool.  Mirrors the"
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

# UNLOCK ONCE, HERE.  Every step below signs, and on a current devnet the keyring is the encrypted
# `file` backend.  Without this the first key access prompts raw from qadenad with no indication of
# which keyring it means, or -- with no tty -- hangs with no prompt at all; qadena_keyring_unlock
# asks once, names the keyring, and fails with the remedy when it cannot ask.  AFTER the argument
# loop, so --help never prompts.
qadena_keyring_unlock

# check if "treasury" key exists by "qadenad "
if qadenad_alias keys show treasury > /dev/null 2>&1; then
    echo "treasury key already exists"
else
    echo "treasury key not found, adding it now"
    # `keys add --recover` reads the mnemonic from stdin, then the passphrase.  _raw feeds
    # nothing, so the call site owns that ordering; qadenad_alias would replace stdin.
    { echo "$config_yml_treasurymnemonic"
      [ -z "${QADENA_KEYRING_PASS:-}" ] || { echo "$QADENA_KEYRING_PASS"; echo "$QADENA_KEYRING_PASS"; }
    } | qadenad_alias_raw keys add treasury --recover
fi





#
count=2

echo "-------------------------"
echo "Staking from treasury to $pioneer"
echo "-------------------------"

# need to stake from treasury to pioneer1, do this only once
$qadenatestscripts/gov_stake_from_treasury.sh $pioneer 10000000qdn


# --deployment is passed only in sponsored mode, which is the only mode that creates an admin key.
# It selects ekycph-admin and ~/ekyc-ph from foundation_scripts/deployment_profile.sh; without it
# step_1 names the admin sec-veritas-admin, which setup_veritas.sh also uses.
# banksend creates no admin key and keeps its original invocation.
# Validated here, before anything is written: every branch below tests for banksend and treats
# anything else as sponsored, so an unrecognised value must not reach them.
case "$fund_mode" in
    foundation-sponsored|banksend) ;;
    *) echo "unknown --fund-mode '$fund_mode' (foundation-sponsored | banksend)"; exit 1 ;;
esac

# The sponsor accounts are funded before step_1, which needs their addresses: sponsored mode
# writes them into variables.json and derives every pre-grant from them.
step1_extra=()
step23_extra=()
if [ "$fund_mode" != "banksend" ]; then
    echo "-------------------------"
    echo "Toll-free: funding two foundation accounts, no $treasuryname"
    echo "-------------------------"
    # setup_foundation_accounts.sh owns these two accounts: recovers them from their fixed dev
    # mnemonics and tops up the funding.  Idempotent.
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
# The foundation's first action, between step_1 and step_2.  In sponsored mode every wallet step_2
# creates is paid for by a fee grant issued against it in advance; without this, create-wallet
# fails with "fee-grant not found".  --foundation-appsvr names the shared devnet account.
if [ "$fund_mode" != "banksend" ]; then
    echo "-------------------------"
    echo "FOUNDATION: delegate grant authority and pre-grant every wallet"
    echo "-------------------------"
    # step_1 wrote this into the deployment's state directory -- the profile's DEPLOY_SEC_HOME,
    # which --deployment ekycph selected, unless the caller pointed VERITAS_SEC_HOME elsewhere.
    _pregrant="$ekycph_home/pregrant_addresses.json"
    [ -r "$_pregrant" ] || { echo "FAILED: no $_pregrant -- step_1 did not complete"; exit 1; }
    $qadenafoundationscripts/ekycph_after_step_1.sh --pregrant "$_pregrant" \
        --foundation-appsvr "$foundation_appsvr"
fi

$veritasscripts/step_2.sh "${step23_extra[@]}"

# read proposal id from ekycphidentity.proposal_id
ekycphidentityproposal_id=$(cat $qadenaproviderscripts/proposals/ekycphidentitysrvprv.proposal_id)
ekycphdsvsproposal_id=$(cat $qadenaproviderscripts/proposals/ekycphdsvssrvprv.proposal_id)

# Skip the deposit and vote when the provider is already registered.  setup_provider_base.sh
# submits a proposal every run, and one that re-registers an existing provider passes the vote and
# fails on execution.  The chain is the authority here, not the .proposal_id file, which is
# overwritten every run and says nothing about registration.
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
# Step 4, the foundation's final action.  It lives in foundation_scripts/ekycph_after_step_3.sh
# because every grant it issues is signed by the foundation and authz cannot be sub-delegated.
# --foundation-users/-appsvr name the shared devnet pair.
if [ "$fund_mode" != "banksend" ]; then
    # --pool-addresses, not --count: --count derives the pool names and resolves them in the
    # coordinator keyring, which on a devnet is the node's home, not ~/ekyc-ph.  step_3 already
    # wrote the addresses, and passing them needs no keyring.
    _pool="$ekycph_home/pool_addresses.json"
    [ -r "$_pool" ] || { echo "FAILED: no $_pool -- step_3 did not complete"; exit 1; }
    $qadenafoundationscripts/ekycph_after_step_3.sh --pool-addresses "$_pool" \
        --foundation-users "$foundation_users" \
        --foundation-appsvr "$foundation_appsvr"
fi

echo "These go into env-ekycph-dev"

# WHERE step_3 ACTUALLY WROTE THEM.  extract_ephem_keys.sh is called with
# --out-dir "$VERITAS_SEC_HOME" (veritas_scripts/step_3.sh:590), so these files live in the
# DEPLOYMENT HOME -- not the directory the operator happened to start from.  Reading them as bare
# relative names ended a completely SUCCESSFUL deploy with ten "No such file or directory" lines
# and ten empty values, which reads exactly like the keys were never created.  The home first,
# the CWD kept as a fallback for output left by an older run that wrote there.
# NOT a bare `cat`: a missing file under `set -e` kills the script at its very last step, after
# everything worked.  A marker line is both survivable and more visible than a cat error.
emit_key_var() {
    local var="$1" name="$2" _c file=""
    for _c in "$ekycph_home/$name" "$name"; do
        [ -f "$_c" ] && { file="$_c"; break; }
    done
    if [ -n "$file" ]; then
        echo "$var='`cat $file`'"
    else
        echo "$var=<MISSING: $name in neither $ekycph_home nor $PWD>"
        echo "WARNING: $name not found -- step_3 writes it to $ekycph_home" >&2
    fi
}

# echo the contents of each of the names and keys
emit_key_var SEC_DSVS_EPH_USERNAME "$dsvsname-names.base64"
emit_key_var SEC_DSVS_EPH_PRIVATE_KEY "$dsvsname-keys.base64"

emit_key_var SEC_DSVS_EPH_CREDENTIAL_USERNAME "$dsvsname-credential-names.base64"
emit_key_var SEC_DSVS_EPH_CREDENTIAL_PRIVATE_KEY "$dsvsname-credential-keys.base64"

emit_key_var SEC_DSVS_SRV_PRV_USERNAME "$dsvsprovidername-names.base64"
emit_key_var SEC_DSVS_SRV_PRV_PRIVATE_KEY "$dsvsprovidername-keys.base64"

emit_key_var SEC_IDENTITY_SRV_PRV_USERNAME "$identityprovidername-names.base64"
emit_key_var SEC_IDENTITY_SRV_PRV_PRIVATE_KEY "$identityprovidername-keys.base64"

emit_key_var SEC_CREATE_WALLET_SPONSOR_USERNAME "$createwalletsponsorname-names.base64"
emit_key_var SEC_CREATE_WALLET_SPONSOR_PRIVATE_KEY "$createwalletsponsorname-keys.base64"
