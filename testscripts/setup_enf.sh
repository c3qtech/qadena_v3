#!/bin/zsh

set -e

# get script dir
SCRIPT_DIR="${0:A:h}"

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

with_contracts=false
force_contracts=false

# Captured at top level: inside a zsh function $0 is the FUNCTION's name, so using it directly in
# usage() prints "Usage: usage [...]".
me="$0"

usage() {
    echo "Usage: $me [--pioneer <pioneer>] [--with-contracts] [--force-contracts]"
    echo ""
    echo "  --with-contracts   also compile and deploy the ENF notarial book contract:"
    echo "                     optimizer.sh, then enf_cli.sh setup-enf / upload / instantiate."
    echo "                     Chain-only -- it does NOT register the contract with the"
    echo "                     app-server, which does not exist yet at this point."
    echo "  --force-contracts  upload and instantiate even when enf_state.json already"
    echo "                     records a contract address, replacing it with a fresh one."
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
        --with-contracts)
            with_contracts=true
            shift
            ;;
        --force-contracts)
            force_contracts=true
            with_contracts=true
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

# --with-contracts runs docker and a wasm toolchain at the very END of a long chain setup.  Finding
# out then that docker is absent means redoing all of it, so establish it now.
enfdir="$qadenabuild/enf-smart-contracts"
if [ "$with_contracts" = "true" ]; then
    [ -x "$enfdir/enf_cli.sh" ] || { echo "FAILED: no enf_cli.sh at $enfdir"; exit 1; }
    [ -f "$enfdir/optimizer.sh" ] || { echo "FAILED: no optimizer.sh at $enfdir"; exit 1; }
    command -v docker > /dev/null 2>&1 || {
        echo "FAILED: --with-contracts needs docker to compile the contract (cosmwasm/optimizer)."
        echo "        Install docker, or drop --with-contracts and run enf-smart-contracts/optimizer.sh"
        echo "        and enf_cli.sh by hand once it is available."
        exit 1; }
    docker info > /dev/null 2>&1 || {
        echo "FAILED: docker is installed but the daemon is not reachable; the contract compiles inside it."
        exit 1; }
    command -v jq > /dev/null 2>&1 || { echo "FAILED: jq is required to read enf_state.json"; exit 1; }
    echo "--with-contracts: docker is available, will deploy the contract after the chain setup"
fi

# check if "treasury" key exists by "qadenad "
if qadenad_alias keys show treasury > /dev/null 2>&1; then
    echo "treasury key already exists"
else
    echo "treasury key not found, adding it now"
    echo $config_yml_treasurymnemonic | qadenad_alias keys add treasury --recover
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
# Keyed on the identity provider's KEY, not on a flag, so it is correct whether ekycph was set up by
# a previous run of this script, by setup_ekycph.sh directly, or not at all.
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

# step_3.sh funds providers and users with `tx bank send` FROM $treasuryname.  Those sends are
# AML-scanned like any other, and a treasury is not a wallet, so without an exemption every one of
# them is refused.  Must land before step_3.sh runs.
echo "-------------------------"
echo "Whitelisting $treasuryname for direct bank sends"
echo "-------------------------"
$qadenatestscripts/whitelist_bank_send.sh $treasuryname \
    "enf deployment treasury: funds providers and users by direct bank send"

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

# ---------------------------------------------------------------------------------------------
# --with-contracts: compile and deploy the ENF notarial book, chain-side only
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
#   start chain -> setup_enf.sh --with-contracts -> bring up the ENF stack -> Makefile registers
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
    # chain-id is constant across reinstalls (qadena_4444-1), so it cannot be used to
    # spot a wiped chain -- and enf_state.json is gitignored local residue that
    # outlives any number of chains.  Asking the chain is both simpler and correct for
    # every reason the contract might be missing: chain wiped, wrong node, contract
    # removed, state file hand-edited.
    #
    # Skipping deployment against a phantom address is the worst available outcome:
    # the stack comes up, setup-backend registers an address that does not exist, and
    # the first real failure surfaces somewhere else entirely.  That cost an afternoon.
    if [ -n "$existing" ] && ! qadenad_alias query wasm contract "$existing" > /dev/null 2>&1; then
        echo "-------------------------"
        echo "Recorded contract $existing is NOT on this chain -- redeploying"
        echo "  (enf_state.json is left over from a previous chain)"
        echo "-------------------------"
        existing=""
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
# These two come from the ekycph identity provider, not from ENF's own.  See the comment on the
# setup_ekycph.sh block above: without that provider on the chain, these are empty and wallet
# creation fails inside the app-server with nothing pointing back here.
echo "REUSABLE_EKYC_APP_NAME='`cat $ekycphidentityprovidername-names.base64`'"
echo "REUSABLE_EKYC_APP_PRIVATE_KEY='`cat $ekycphidentityprovidername-keys.base64`'"

if [ -n "$contract_address" ]; then
    echo ""
    echo "ENF_NOTARIAL_CONTRACT_ADDRESS='$contract_address'"
fi

echo ""
echo "======================================================================"
echo "chain setup complete"
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
    echo ""
    echo "STILL TO DO, OUTSIDE THIS SCRIPT:"
    echo "  1. Deploy the contract:  $0 --with-contracts"
    echo "     (or by hand: cd enf-smart-contracts && ./optimizer.sh && ./enf_cli.sh setup)"
    echo "  2. Bring up the ENF stack (stacks/enf: make up)."
fi
