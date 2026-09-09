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
#
# THESE MNEMONICS ARE HARDCODED LITERALS, SO EVERY KEY DERIVED FROM THEM IS DETERMINISTIC AND
# PUBLIC.  They are checked into a public repository: anyone who reads this file can derive the
# private keys of the ENF treasury, the signer, the create-wallet sponsor, and both service
# providers, and can therefore sign as any of them.
#
# That is exactly what makes a test chain reproducible -- the same script produces the same
# addresses on every machine, so the env vars printed at the end are stable and the veritas steps
# are re-runnable.  It is also why NONE of this may ever be pointed at production.  A production
# deployment must generate its mnemonics off-machine and supply them some other way; there is no
# flag here that makes these safe.

enftreasurymnemonic="crack daughter sister dismiss wall diagram order ready divorce upset anger tomato defense season diesel evolve praise window leopard desk shift fiscal sister blouse"
signermnemonic="correct manage autumn another pass surround item bag educate like bus ugly come such hidden can nasty reason result left clap reject border unit"
createwalletsponsormnemonic="thank omit float build virus oblige tonight slot embark jump actual culture hunt describe stove day decrease breeze card brush danger moral force banner"
identityprovidermnemonic="eye staff snap onion tobacco space phone unfair busy galaxy butter focus puzzle tell patient annual imitate floor town throw shop pizza hungry away"
dsvsprovidermnemonic="depart roast ice mimic gate mass nice practice purse exit force pigeon letter ranch inflict spice potato rent unaware outside observe onion broom decline"


config_yml_treasurymnemonic="eyebrow unaware jealous actor annual farm radio open sword memory other secret twelve reduce festival buddy peace fun film return sniff december february post"

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
# enf to foundation-enf-appsvr/-users -- because the keyring has no namespaces and bucket 10 funds
# more than one programme.  On the devnet there is ONE foundation, one keyring and one chain, and
# all three harnesses run against it in sequence.  Sharing the pair here means no new mnemonics have
# to be invented and committed to a public repo, and it costs nothing: authz and feegrant are keyed
# on (granter, grantee), so three deployments granting from one granter to three disjoint sets of
# grantees do not overwrite each other.
#
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

# Contracts are ON by default; with_contracts is RESOLVED after parsing, not during it, so that the
# flags do not depend on the order they were typed in.  (When --contracts-only set with_contracts
# directly, "--no-contracts --contracts-only" resolved to a contradiction the checker never saw,
# while the reverse order caught it.)
no_contracts=false
force_contracts=false
contracts_only=false

# Captured at top level: inside a zsh function $0 is the FUNCTION's name, so using it directly in
# usage() prints "Usage: usage [...]".
me="$0"

usage() {
    echo "Usage: $me [--pioneer <pioneer>] [--fund-mode <mode>] [--no-contracts]"
    echo "           [--contracts-only] [--force-contracts]"
    echo ""
    echo "  By default this does BOTH halves: the chain setup, then compile and deploy of the"
    echo "  ENF notarial book contract (optimizer.sh, then enf_cli.sh setup-enf / upload /"
    echo "  instantiate).  Chain-side only -- it does NOT register the contract with the"
    echo "  app-server, which does not exist yet at this point; the stacks/enf Makefile does"
    echo "  that after 'make up'."
    echo ""
    echo "  --fund-mode <mode> foundation-sponsored (default) | banksend."
    echo "                     foundation-sponsored: the foundation pays by fee grant, ENF holds"
    echo "                     no tokens and gets its own admin key, its own ~/sec-enf state and"
    echo "                     its own sponsor pool.  Mirrors foundation_scripts/enf_*.sh."
    echo "                     banksend: the original 2M qdn into enf-treasury plus an AML"
    echo "                     whitelist exemption.  Kept for a deployment mid-migration."
    echo "  --no-contracts     do the chain setup only and stop before the contract."
    echo "  --contracts-only   skip the chain setup and deploy the contract only.  THIS is how"
    echo "                     to add contracts to a chain that was already set up -- the chain"
    echo "                     half is not re-runnable, so re-running the whole script on a"
    echo "                     chain it has already prepared fails partway through."
    echo "                     --only-contracts is accepted as an alias."
    echo "  --force-contracts  upload and instantiate even when enf_state.json already"
    echo "                     records a contract address, replacing it with a fresh one."
    echo "  --with-contracts   accepted and ignored -- contracts are the default now.  Kept so"
    echo "                     existing invocations and docs do not break."
}

# accept 1 parameter, the pioneer name
# accept named parameters to override all these mnemonics
# Process command line arguments
#
# PARSED BEFORE ANYTHING IS WRITTEN.  Every step below this point mutates the chain or the keyring,
# so a mistyped flag has to fail while that is still true of nothing.
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
        --with-contracts)
            # No-op: this is the default.  Still accepted because it is in every doc, comment and
            # shell history that predates the switch, and failing on it would be pure friction.
            shift
            ;;
        --no-contracts)
            no_contracts=true
            shift
            ;;
        --contracts-only|--only-contracts)
            # Both spellings: --no-contracts / --with-contracts put the noun last, so that is the
            # order the hand reaches for, and having one of them be an "unknown option" that exits 1
            # is a pointless way to lose a run.
            contracts_only=true
            shift
            ;;
        --force-contracts)
            force_contracts=true
            shift
            ;;
        --help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# A TYPO MUST NOT MEAN "SPONSORED".  Every branch below is `if banksend ... else sponsored`, so
# --fund-mode banksned would run the sponsored path -- creating an admin key and a sponsor pool for
# an operator who asked for the opposite.  Checked here, with the other contradictions, before
# anything is written.
case "$fund_mode" in
    foundation-sponsored|banksend) ;;
    *) echo "FAILED: unknown --fund-mode '$fund_mode' (foundation-sponsored | banksend)"; exit 1 ;;
esac

if [ "$no_contracts" = "true" ]; then
    if [ "$contracts_only" = "true" ]; then
        echo "FAILED: --no-contracts and --contracts-only are contradictory"
        usage
        exit 1
    fi
    if [ "$force_contracts" = "true" ]; then
        echo "FAILED: --no-contracts and --force-contracts are contradictory"
        usage
        exit 1
    fi
    with_contracts=false
else
    with_contracts=true
fi

# The contract half runs docker and a wasm toolchain at the very END of a long chain setup.  Finding
# out then that docker is absent means redoing all of it, so establish it now.
enfdir="$qadenabuild/enf-smart-contracts"
if [ "$with_contracts" = "true" ]; then
    [ -x "$enfdir/enf_cli.sh" ] || { echo "FAILED: no enf_cli.sh at $enfdir"; exit 1; }
    [ -f "$enfdir/optimizer.sh" ] || { echo "FAILED: no optimizer.sh at $enfdir"; exit 1; }
    command -v docker > /dev/null 2>&1 || {
        echo "FAILED: deploying the contract needs docker (cosmwasm/optimizer compiles inside it)."
        echo "        Install docker, or pass --no-contracts and run enf-smart-contracts/optimizer.sh"
        echo "        and enf_cli.sh by hand once it is available."
        exit 1; }
    docker info > /dev/null 2>&1 || {
        echo "FAILED: docker is installed but the daemon is not reachable; the contract compiles inside it."
        exit 1; }
    command -v jq > /dev/null 2>&1 || { echo "FAILED: jq is required to read enf_state.json"; exit 1; }
    echo "contracts: docker is available, the contract will be deployed"
fi

# --contracts-only presupposes the chain half already ran.  Check that here rather than letting
# enf_cli.sh setup-enf discover it: create_user.sh needs the create-wallet sponsor to pay for the
# ENF deployer's wallet and the identity provider to issue its credentials, and when either is
# missing it fails deep inside a sub-script with a message that says nothing about this flag.
if [ "$contracts_only" = "true" ]; then
    for required_key in "$createwalletsponsorname" "$identityprovidername"; do
        qadenad_alias keys show "$required_key" > /dev/null 2>&1 || {
            echo "FAILED: --contracts-only, but '$required_key' is not in the keyring."
            echo "        That key is made by the chain setup, so this chain has not had it run."
            echo "        Run $me (no flags) instead -- it does both halves."
            exit 1; }
    done
    echo "--contracts-only: chain setup already ran, skipping straight to the contract"
fi

# ---------------------------------------------------------------------------------------------
# The chain half.  Skipped entirely by --contracts-only.
# ---------------------------------------------------------------------------------------------
#
# THIS SECTION IS NOT RE-RUNNABLE.  Individual pieces guard themselves -- the key blocks below,
# setup_treasury.sh, enf_cli.sh setup-enf -- but the governance steps do not: step_1.sh/step_2.sh
# submit fresh service-provider proposals, and the deposit/vote here then run against proposals
# that have already passed.  That is why adding contracts to an already-prepared chain is
# --contracts-only and not a second full run.
if [ "$contracts_only" != "true" ]; then

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

# ENF CANNOT STAND ALONE: IT NEEDS THE EKYCPH PROVIDER.  This is not a convenience -- the env vars
# printed at the end include REUSABLE_EKYC_APP_NAME and REUSABLE_EKYC_APP_PRIVATE_KEY, taken from
# $ekycphidentityprovidername.  The ENF app-server signs reusable-eKYC calls as that provider, so on
# a chain where only setup_enf.sh has run, the provider is absent and WALLET CREATION FAILS.
#
# It fails in the worst possible way: nothing here errors, the chain setup reports success, every
# provider proposal passes, and the breakage surfaces later inside the app-server as a wallet
# creation that does not work, with nothing pointing back at a missing provider on the chain.  That
# gap cost a full day of debugging, which is why this block auto-runs the other org's script instead
# of assuming somebody remembered to.
#
# KEYED ON THE CHAIN, NOT ON THE LOCAL KEYRING.  This used to ask `keys show` for the ekycph
# identity provider, which was right while every deployment shared one keyring.  Sponsored mode
# gives each deployment its own state directory (~/sec-ekycph), so ekycph's keys are no longer in
# the node keyring and the check reported "not found" for a deployment that was fully set up.  It
# then re-ran setup_ekycph.sh, which resubmitted the two provider proposals -- and those FAILED on
# execution, because what they register already existed.  Measured on qadena_4828-1, 2026-09-09.
#
# The chain is the authority anyway: what ENF needs is that the provider is REGISTERED, which is
# exactly what the app-server will require at runtime, and it is true regardless of which keyring
# holds the key or which machine ran the setup.
_ekycph_registered=$(qadenad_alias query qadena list-interval-public-key-id --output json 2>/dev/null \
    | sed -n '/^{/,$p' \
    | jq -r --arg n "$ekycphidentityprovidername" \
        '(.intervalPublicKeyID // [])[] | select(.nodeID==$n) | .pubKID' 2>/dev/null | head -1)
if [ -n "$_ekycph_registered" ]; then
    echo "$ekycphidentityprovidername already registered on chain ($_ekycph_registered)"
else
    echo "$ekycphidentityprovidername not registered on chain, setting up ekycph..."
    # Pass the fund mode through: an ENF run asked for sponsored must not silently bring up ekycph
    # in banksend mode, which would give it a treasury and an AML whitelist exemption nobody asked
    # for and leave the two deployments funded differently on the same chain.
    $qadenatestscripts/setup_ekycph.sh --pioneer "$pioneer" --fund-mode "$fund_mode"
fi

#
count=2

echo "-------------------------"
echo "Staking from treasury to $pioneer"
echo "-------------------------"

# need to stake from treasury to pioneer1, do this only once
$qadenatestscripts/gov_stake_from_treasury.sh $pioneer 10000000qdn


# --deployment IS PASSED ONLY IN SPONSORED MODE, and that is deliberate.
#
# It gives ENF its own admin key (enf-admin) and its own state directory (~/sec-enf) out of
# foundation_scripts/deployment_profile.sh.  Both are REQUIRED here and not merely tidy: sponsored
# mode is the only mode that creates an admin key, and without --deployment step_1 would name it
# sec-veritas-admin -- the same key setup_veritas.sh creates, in the same keyring, on the same
# devnet, which ENF and ekycph both share.  The last harness to run would silently adopt the first
# one's admin identity.
#
# banksend keeps EXACTLY its previous invocation, down to the shared ~/sec-veritas state directory.
# It creates no admin key so it cannot collide, and a working legacy path is worth more than
# consistency with a mode it does not use.
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
    # Doing it this way rather than requiring setup_veritas.sh to have run first matters: enf
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

    step1_extra=(--deployment enf --appsvr "$_appsvr_addr" --users "$_users_addr")
    step23_extra=(--deployment enf)
fi
$veritasscripts/step_1.sh "${step1_extra[@]}" --count $count --provideramount $provideramount --signeramount $signeramount --createwalletsponsoramount $createwalletsponsoramount --createwalletsponsorname $createwalletsponsorname --pioneer $pioneer --treasurymnemonic $enftreasurymnemonic --signermnemonic $signermnemonic --createwalletsponsormnemonic $createwalletsponsormnemonic --identityprovidermnemonic $identityprovidermnemonic --dsvsprovidermnemonic $dsvsprovidermnemonic --treasuryname $treasuryname --identityprovidername $identityprovidername --dsvsprovidername $dsvsprovidername --email $email --avalue $avalue --firstname $firstname --birthdate $birthdate --phone $phone --dsvsname $dsvsname


# FUNDING.  Two shapes, selected by $fund_mode -- the same two setup_veritas.sh offers.
#
# foundation-sponsored (default) -- NO enf TREASURY AT ALL.  The foundation pays by fee grant and
#   ENF holds no tokens.  Two foundation accounts rather than one, because the populations behave
#   differently:
#
#     foundation-appsvr  ENF's own operational wallets.  A FIXED set, known at deployment, so they
#                        are granted directly, once, here.  No key of ENF's can spend the
#                        foundation's money -- only present these grants.
#     foundation-users   citizen wallets.  These appear continuously, so the app-server issues their
#                        grants at runtime via authz.  That delegation is unbounded by nature, and
#                        keeping it on a separate account confines it to the user float.
#
# banksend -- the original: 2M qdn into enf-treasury, an AML whitelist exemption so that treasury can
#   make direct bank sends at all, and a fan-out of one transfer per wallet.
if [ "$fund_mode" = "banksend" ]; then
    # grants 2M qdn from "treasury" to "enf-treasury"
    echo "-------------------------"
    echo "Granting 2M qdn from treasury to enf-treasury"
    echo "-------------------------"
    $qadenatestscripts/grant_from_treasury.sh $treasuryname 2000000qdn

    # step_3.sh funds providers and users with `tx bank send` FROM $treasuryname.  Those sends are
    # AML-scanned like any other, and a treasury is not a wallet, so without an exemption every one
    # of them is refused.  Must land before step_3.sh runs.
    echo "-------------------------"
    echo "Whitelisting $treasuryname for direct bank sends"
    echo "-------------------------"
    $qadenatestscripts/whitelist_bank_send.sh $treasuryname \
        "enf deployment treasury: funds providers and users by direct bank send"
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
    # which --deployment enf selected, unless the caller pointed VERITAS_SEC_HOME elsewhere.
    _pregrant="${VERITAS_SEC_HOME:-$HOME/sec-enf}/pregrant_addresses.json"
    [ -r "$_pregrant" ] || { echo "FAILED: no $_pregrant -- step_1 did not complete"; exit 1; }
    $qadenafoundationscripts/enf_after_step_1.sh --pregrant "$_pregrant" \
        --foundation-appsvr "$foundation_appsvr"
fi

$veritasscripts/step_2.sh "${step23_extra[@]}"

# read proposal id from enfidentity.proposal_id
enfidentityproposal_id=$(cat $qadenaproviderscripts/proposals/enfidentitysrvprv.proposal_id)
enfdsvsproposal_id=$(cat $qadenaproviderscripts/proposals/enfdsvssrvprv.proposal_id)

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

for _spec in "enfidentitysrvprv:$enfidentityproposal_id" "enfdsvssrvprv:$enfdsvsproposal_id"; do
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
# In foundation_scripts/enf_after_step_3.sh rather than inlined, because in a real deployment this
# is NOT ENF's to run: every grant it issues is signed by the foundation, and authz cannot be
# sub-delegated, so ENF could not do it even with the step_1 authorisation.  This harness calls it
# because it plays both roles and holds every key in one keyring -- which is exactly why it cannot
# tell the difference and the split has to be enforced by where the code lives.
#
# --foundation-users/-appsvr override the profile's production names with the shared devnet pair.
if [ "$fund_mode" != "banksend" ]; then
    # --pool-addresses, NOT --count.  With --count this DERIVES the pool wallet names and resolves
    # each in the coordinator keyring, which on a devnet defaults to the NODE's home -- but the
    # deployment's keys live in ~/sec-enf.  Every lookup missed and it reported
    #     SKIPPED enf-create-wallet-sponsor -- not resolvable in ~/qadena
    #     authorised 0 wallet(s); 3 incomplete
    # while exiting 0, so only the verifier caught it.  step_3 already wrote the ADDRESSES; passing
    # them needs no keyring at all.
    _pool="${VERITAS_SEC_HOME:-$HOME/sec-enf}/pool_addresses.json"
    [ -r "$_pool" ] || { echo "FAILED: no $_pool -- step_3 did not complete"; exit 1; }
    $qadenafoundationscripts/enf_after_step_3.sh --pool-addresses "$_pool" \
        --foundation-users "$foundation_users" \
        --foundation-appsvr "$foundation_appsvr"
fi

fi  # end of the chain half

# ---------------------------------------------------------------------------------------------
# Compile and deploy the ENF notarial book, chain-side only (skipped by --no-contracts)
# ---------------------------------------------------------------------------------------------
#
# WHERE THE LINE IS DRAWN, AND WHY.  enf_cli.sh's `setup` chains setup-enf -> upload -> instantiate
# -> setup-backend.  The first three talk only to the chain.  The fourth POSTs to ENF_API_BASE
# (default http://localhost:3002) to hand the contract address and signing keys to a RUNNING
# app-server -- which by definition does not exist yet, because this script is what prepares the
# chain the app-server will connect to.
#
# So this runs the first three and stops.  There is deliberately no wait-for-API loop: waiting would
# only convert "the stack is not up" from an immediate, obvious failure into a timeout at the end of
# a twenty-minute setup.  Registration is now the app-server's own concern -- it exposes
# GET /v1/enf/setup_enf returning {"configured","contractAddress","runtimeReady"}, and the stacks/enf
# Makefile calls `enf_cli.sh setup-backend` after `up` only when configured is false.
#
#   start chain -> setup_enf.sh -> bring up the ENF stack -> Makefile registers
#
contract_address=""
if [ "$with_contracts" = "true" ]; then
    echo "-------------------------"
    echo "Compiling the ENF notarial book contract"
    echo "-------------------------"

    # optimizer.sh mounts "$(pwd)" into the container, so it is only correct when run FROM the
    # contract directory.  A subshell keeps that cd from leaking: the .base64 reads at the end of
    # this script are relative to the caller's directory.
    ( cd "$enfdir" && ./optimizer.sh ) || { echo "FAILED: optimizer.sh could not build the contract"; exit 1; }

    echo "-------------------------"
    echo "Creating the ENF deployer keys"
    echo "-------------------------"
    # setup-enf is itself idempotent -- it returns early when enf_state.json already records an
    # enf_address, and skips create_user.sh when the key exists -- so it needs no guard here.
    "$enfdir/enf_cli.sh" setup-enf || { echo "FAILED: enf_cli.sh setup-enf"; exit 1; }

    # UPLOAD AND INSTANTIATE ARE NOT IDEMPOTENT.  Each upload stores a new code_id and each
    # instantiate produces a NEW contract address, silently orphaning whatever the app-server was
    # configured with.  enf_cli.sh records the address in enf_state.json, so that is the thing to
    # check.  stdout is clean here -- setup_env.sh writes its banner to stderr.
    existing=$("$enfdir/enf_cli.sh" contract-addr 2>/dev/null | tail -1)

    # A recorded address only means something if the contract is still THERE.  The
    # chain-id is constant across reinstalls (qadena_4828-1), so it cannot be used to
    # spot a wiped chain -- and enf_state.json is gitignored local residue that
    # outlives any number of chains.  Asking the chain is both simpler and correct for
    # every reason the contract might be missing: chain wiped, wrong node, contract
    # removed, state file hand-edited.
    #
    # Skipping deployment against a phantom address is the worst available outcome:
    # the stack comes up, setup-backend registers an address that does not exist, and
    # the first real failure surfaces somewhere else entirely.  That cost an afternoon.
    # EXISTENCE IS NOT ENOUGH -- IT MUST ALSO BE OURS.  wasm contract addresses are derived
    # deterministically from code_id and instance sequence, so a rebuilt chain that replays the same
    # work in the same order re-mints the SAME addresses.  Observed exactly that: after wiping the
    # chain and re-running regression, testscripts/test_enf_contracts.sh instantiated at block 1974
    # and landed on the very address a previous chain's setup_enf had left in enf_state.json.  The
    # existence check passed truthfully, deployment was skipped, and ENF_NOTARIAL_CONTRACT_ADDRESS
    # pointed at a contract owned by the regression signer -- one that the next regression run drops
    # and redeploys over.
    #
    # So compare the CREATOR against the ENF deployer.  setup-enf has already run by this point, so
    # the key exists and the keyring is as fresh as the chain is.
    if [ -n "$existing" ]; then
        contract_json=$(qadenad_alias query wasm contract "$existing" --output json 2>/dev/null) || contract_json=""
        contract_creator=$(echo "$contract_json" | jq -r '.contract_info.creator // empty' 2>/dev/null)
        enf_deployer=$(qadenad_alias keys show ENF -a --keyring-backend test 2>/dev/null)

        if [ -z "$contract_creator" ]; then
            echo "-------------------------"
            echo "Recorded contract $existing is NOT on this chain -- redeploying"
            echo "  (enf_state.json is left over from a previous chain)"
            echo "-------------------------"
            existing=""
        elif [ -n "$enf_deployer" ] && [ "$contract_creator" != "$enf_deployer" ]; then
            echo "-------------------------"
            echo "Recorded contract $existing exists but was NOT deployed by ENF -- redeploying"
            echo "  creator:      $contract_creator"
            echo "  ENF deployer: $enf_deployer"
            echo "  (deterministic wasm addresses mean a stale enf_state.json can name a real"
            echo "   contract belonging to something else -- e.g. the regression suite)"
            echo "-------------------------"
            existing=""
        fi
    fi

    if [ -n "$existing" ] && [ "$force_contracts" != "true" ]; then
        echo "-------------------------"
        echo "Contract already deployed: $existing"
        echo "  (skipping upload/instantiate; pass --force-contracts to replace it)"
        echo "-------------------------"
        contract_address="$existing"
    else
        if [ -n "$existing" ]; then
            echo "--force-contracts: replacing the recorded contract $existing"
        fi
        echo "-------------------------"
        echo "Uploading the contract wasm"
        echo "-------------------------"
        "$enfdir/enf_cli.sh" upload || { echo "FAILED: enf_cli.sh upload"; exit 1; }

        echo "-------------------------"
        echo "Instantiating the contract"
        echo "-------------------------"
        "$enfdir/enf_cli.sh" instantiate || { echo "FAILED: enf_cli.sh instantiate"; exit 1; }

        contract_address=$("$enfdir/enf_cli.sh" contract-addr 2>/dev/null | tail -1)
        [ -n "$contract_address" ] || { echo "FAILED: instantiate recorded no contract address"; exit 1; }
    fi
fi

echo "These go into env-enf-dev"

# extract_ephem_keys.sh writes these files into the CALLER'S CWD, not anywhere derived from
# $SCRIPT_DIR -- so on a full run they are here because step_3.sh just put them here, but under
# --contracts-only they are only here if this run happens to share a cwd with the run that made
# them.  A bare `cat` on a missing one dies under `set -e`, which would kill the script at the very
# last step -- after a successful deploy, before ENF_NOTARIAL_CONTRACT_ADDRESS is ever printed.
# Print a marker instead, which is also more visible than a cat error buried in this output.
emit_key_var() {
    local var="$1" file="$2"
    if [ -f "$file" ]; then
        echo "$var='`cat $file`'"
    else
        echo "$var=<MISSING: no $file in $PWD>"
        echo "WARNING: $file not found in $PWD -- rerun from the directory the setup wrote it to" >&2
    fi
}

# echo the contents of each of the names and keys
emit_key_var SEC_DSVS_EPH_USERNAME "$dsvsname-names.base64"
emit_key_var SEC_DSVS_EPH_PRIVATE_KEY "$dsvsname-keys.base64"

echo ""

emit_key_var SEC_DSVS_EPH_CREDENTIAL_USERNAME "$dsvsname-credential-names.base64"
emit_key_var SEC_DSVS_EPH_CREDENTIAL_PRIVATE_KEY "$dsvsname-credential-keys.base64"

echo ""

emit_key_var SEC_DSVS_SRV_PRV_USERNAME "$dsvsprovidername-names.base64"
emit_key_var SEC_DSVS_SRV_PRV_PRIVATE_KEY "$dsvsprovidername-keys.base64"

echo ""

emit_key_var SEC_IDENTITY_SRV_PRV_USERNAME "$identityprovidername-names.base64"
emit_key_var SEC_IDENTITY_SRV_PRV_PRIVATE_KEY "$identityprovidername-keys.base64"

echo ""

emit_key_var SEC_CREATE_WALLET_SPONSOR_USERNAME "$createwalletsponsorname-names.base64"
emit_key_var SEC_CREATE_WALLET_SPONSOR_PRIVATE_KEY "$createwalletsponsorname-keys.base64"

echo ""

# These two come from the ekycph identity provider, not from ENF's own.  See the comment on the
# setup_ekycph.sh block above: without that provider on the chain, these are empty and wallet
# creation fails inside the app-server with nothing pointing back here.
emit_key_var REUSABLE_EKYC_APP_NAME "$ekycphidentityprovidername-names.base64"
emit_key_var REUSABLE_EKYC_APP_PRIVATE_KEY "$ekycphidentityprovidername-keys.base64"

if [ -n "$contract_address" ]; then
    echo ""
    echo "ENF_NOTARIAL_CONTRACT_ADDRESS='$contract_address'"
fi

echo ""
echo "======================================================================"
if [ "$contracts_only" = "true" ]; then
    echo "contract deployment complete (chain setup was skipped)"
else
    echo "chain setup complete"
fi
echo "======================================================================"
if [ "$with_contracts" = "true" ]; then
    echo "Deployed: $contract_address"
    echo ""
    echo "STILL TO DO, OUTSIDE THIS SCRIPT:"
    echo "  1. Bring up the ENF stack (stacks/enf: make up)."
    echo ""
    echo "That is all.  Registering the contract with the app-server is automatic: the Makefile"
    echo "checks GET /v1/enf/setup_enf after 'up' and calls 'enf_cli.sh setup-backend' only when"
    echo "it reports configured=false.  This script deliberately does not do it -- the app-server"
    echo "is not running yet at this point, and waiting for it here would turn an obvious failure"
    echo "into a timeout at the end of a long setup."
else
    # --contracts-only, NOT a bare re-run: everything above has already happened on this chain, and
    # the governance steps in the chain half would run a second time against proposals that have
    # already passed.  Telling somebody to re-run the whole script here sends them into a failure
    # twenty minutes deep, which is exactly the advice this line used to give.
    echo ""
    echo "STILL TO DO, OUTSIDE THIS SCRIPT:"
    echo "  1. Deploy the contract:  $me --contracts-only"
    echo "     (or by hand: cd enf-smart-contracts && ./optimizer.sh && ./enf_cli.sh setup)"
    echo "     Do NOT just re-run $me -- the chain setup above is not re-runnable."
    echo "  2. Bring up the ENF stack (stacks/enf: make up)."
fi
