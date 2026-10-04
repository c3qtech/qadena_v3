#!/bin/zsh
#
# setup_epdc.sh -- prepare a devnet chain for the e-PDC app-server, the way setup_enf.sh does for ENF.
#
#   ./testscripts/setup_epdc.sh                    # onboard epdc, then deploy the register contract
#   ./testscripts/setup_epdc.sh --contracts-only   # skip onboarding; contract half only
#   ./testscripts/setup_epdc.sh --no-contracts     # onboarding only
#   ./testscripts/setup_epdc.sh --rebuild          # rebuild the wasm first
#   ./testscripts/setup_epdc.sh --force-contracts  # replace a recorded contract
#
# then, once the epdc stack is up (follow-the-money):
#   make -C stacks/epdc setup-backend-if-needed
#
# TWO HALVES, like setup_enf.sh.
#
# THE CHAIN HALF onboards epdc as a deployment of its own through the same veritas steps every other
# deployment uses (setup_ekycph.sh is the template), driven by the `epdc` profile in
# foundation_scripts/deployment_profile.sh:
#   step_1 --deployment epdc  -> epdc's keys: treasury, signer, create-wallet sponsor, identity and
#                                DSVS provider keys, admin
#   epdc_after_step_1.sh      -> FOUNDATION: authz to epdc's admin + the wallet pre-grants
#   step_2 --deployment epdc  -> the two service providers, epdcidentitysrvprv and epdcdsvssrvprv,
#                                each registered by a governance proposal (deposit + vote here)
#   step_3 --deployment epdc  -> the DSVS user epdcdsvs with its ephemeral signing wallets, the
#                                sponsor pool, and the <name>-names/-keys.base64 files
#   epdc_after_step_3.sh      -> FOUNDATION: the app-server's sponsor pool grants
# It prints the EPDC_* key lines the epdc api loads: the DSVS service provider creates each
# issuance and certificate document, epdcdsvs's wallets are the api's document-signing queue, and
# the identity provider + create-wallet sponsor pool drive custodial payor signing.
# EPDC_*, not the SEC_* names the other deployments print: e-PDC has nothing to do with SEC.
#
# THE CONTRACT HALF deploys the epdc-register contract with epdc_cli.sh: the EPDC deployer /
# orchestrator wallet, upload + instantiate (skipped when a recorded contract is on this chain AND
# was created by EPDC -- the setup_enf.sh guard), and the three demo attestors.
#
# THE MNEMONICS BELOW ARE HARDCODED LITERALS, SO EVERY KEY DERIVED FROM THEM IS DETERMINISTIC AND
# PUBLIC -- the same trade setup_enf.sh documents: reproducible test chains, never production.
#
# extract_ephem_keys.sh (inside step_3) writes the .base64 files into the CALLER'S CWD, and the
# lines printed at the end read them from there -- so run the contract-only pass from the same
# directory as the onboarding run if you want those lines reprinted.

set -e

SCRIPT_DIR="${0:A:h}"
source "$SCRIPT_DIR/../scripts/setup_env.sh"
# EXPORT THE RESOLVED BACKEND. setup_env.sh reads it from client.toml (`file` on a current devnet)
# but does not export it, and setup_foundation_accounts.sh forces `test` when it sees it unset --
# so, called from here, it looked in an empty test keyring, "recovered" foundation-appsvr into a
# new unencrypted keyring-test, and failed with "treasury.info: key not found". setup_ekycph.sh and
# setup_enf.sh call it the same way and share the problem on a `file` keyring.
export QADENA_KEYRING_BACKEND
# The epdc profile names the deployment's home (where step_1..3 keep variables.json, the pre-grant
# and pool files). Read from it rather than hardcoding the path in a second place.
source "$SCRIPT_DIR/../foundation_scripts/deployment_profile.sh"
deployment_profile_load epdc || exit 1
epdc_home="${VERITAS_SEC_HOME:-$DEPLOY_SEC_HOME}"

epdctreasurymnemonic="pill vendor fever pen near east venture peace basic melt border toward ignore act health depth cargo true dust result tumble indoor general faculty"
signermnemonic="author crime mercy banner donor good despair runway kick february attend order nation flock print skin account imitate kidney else horror chase later cat"
createwalletsponsormnemonic="blame pencil layer creek divert quality vendor bring leader invite shell pulp good lunar vacant fall twin sunny exhibit axis cigar rude note ability"
identityprovidermnemonic="twice test steel rubber shrug hybrid method foster test upper kind ankle display almost dress result awesome want inject audit sing bubble page impulse"
dsvsprovidermnemonic="pair risk tennis syrup return edge spell faculty year slight salute before abuse unveil prefer volume twin issue diagram arctic pitch ivory butter theme"

config_yml_treasurymnemonic="eyebrow unaware jealous actor annual farm radio open sword memory other secret twelve reduce festival buddy peace fun film return sniff december february post"

provideramount="100000qdn"
signeramount="100000qdn"
createwalletsponsoramount="100000qdn"
foundationamount="2000000qdn"

# THE SAME TWO DEVNET FOUNDATION ACCOUNTS setup_veritas/ekycph/enf use, on purpose: one foundation,
# one keyring, one chain (see setup_enf.sh). The profile's production names
# (foundation-epdc-appsvr/-users) are overridden with these for the devnet.
foundation_appsvr="foundation-appsvr"
foundation_users="foundation-users"
fund_mode="foundation-sponsored"

pioneer="${QADENA_PIONEER:-pioneer1}"
treasuryname="epdc-treasury"
identityprovidername="epdcidentitysrvprv"
dsvsprovidername="epdcdsvssrvprv"
dsvsname="epdcdsvs"
createwalletsponsorname="epdc-create-wallet-sponsor"
email="no-reply@epdc.ph"
# avalue MUST differ from the other deployments' (ekycph 2000, enf 2100): the DSVS user's credential
# id derives from it, and a collision fails quietly -- see enf_cli.sh on "Credential already exists".
avalue="2200"
firstname="EPDC"
birthdate="2025-Jan-01"
phone="+6320000003"
count=2

epdcdir="$SCRIPT_DIR/../epdc-smart-contracts"
cli="$epdcdir/epdc_cli.sh"
with_chain="true"
with_contracts="true"
rebuild="false"
force_contracts="false"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --pioneer)          pioneer="$2"; shift 2 ;;
        --fund-mode)        fund_mode="$2"; shift 2 ;;
        --contracts-only)   with_chain="false"; shift ;;
        --no-contracts)     with_contracts="false"; shift ;;
        --rebuild)          rebuild="true"; shift ;;
        --force-contracts)  force_contracts="true"; shift ;;
        --help|-h)
            echo "Usage: $0 [--pioneer <p>] [--fund-mode foundation-sponsored|banksend]"
            echo "          [--contracts-only | --no-contracts] [--rebuild] [--force-contracts]"
            exit 0 ;;
        *) echo "Unknown option: $1 (try --help)"; exit 1 ;;
    esac
done
case "$fund_mode" in
    foundation-sponsored|banksend) ;;
    *) echo "unknown --fund-mode '$fund_mode' (foundation-sponsored | banksend)"; exit 1 ;;
esac

# The keyring is the encrypted `file` backend on a current devnet, and every step below signs.
qadena_keyring_unlock

echo "========================="
echo "preflight"
echo "========================="
qadenad_alias status > /dev/null 2>&1 || { echo "FAILED: chain is not reachable -- start it first"; exit 1; }
[ "$(qadenad_alias query qadena list-jar-regulator --output json 2>/dev/null | jq -r '.jarRegulator | length' 2>/dev/null)" -gt 0 ] 2>/dev/null || {
    echo "FAILED: no jar regulator on chain -- the enclave is not initialised (see init.sh / run.sh)"; exit 1; }
echo "chain up, enclave initialised"

# Registered providers, keyed on the CHAIN (not the keyring): the same probe setup_ekycph.sh uses.
_registered() {
    qadenad_alias query qadena list-interval-public-key-id --output json 2>/dev/null \
        | sed -n '/^{/,$p' \
        | jq -r --arg n "$1" '(.intervalPublicKeyID // [])[] | select(.nodeID==$n) | .pubKID' 2>/dev/null | head -1
}

# ---------------------------------------------------------------------------------------------
# The chain half.  Skipped by --contracts-only, and when epdc is already onboarded.
# ---------------------------------------------------------------------------------------------
if [ "$with_chain" = "true" ] && [ -n "$(_registered $identityprovidername)" ] && [ -n "$(_registered $dsvsprovidername)" ]; then
    echo "-------------------------"
    echo "epdc is already onboarded ($identityprovidername and $dsvsprovidername are registered) -- skipping the chain half"
    echo "-------------------------"
    with_chain="false"
fi

if [ "$with_chain" = "true" ]; then
    if ! qadenad_alias keys show treasury > /dev/null 2>&1; then
        echo "treasury key not found, adding it now"
        { echo "$config_yml_treasurymnemonic"
          [ -z "${QADENA_KEYRING_PASS:-}" ] || { echo "$QADENA_KEYRING_PASS"; echo "$QADENA_KEYRING_PASS"; }
        } | qadenad_alias_raw keys add treasury --recover
    fi

    echo "-------------------------"
    echo "Staking from treasury to $pioneer"
    echo "-------------------------"
    $qadenatestscripts/gov_stake_from_treasury.sh $pioneer 10000000qdn

    step1_extra=()
    step23_extra=()
    if [ "$fund_mode" != "banksend" ]; then
        echo "-------------------------"
        echo "Toll-free: funding the two foundation accounts, no $treasuryname"
        echo "-------------------------"
        # --appsvr/--users here, and --foundation-appsvr/-users below, override the profile's
        # production names with the shared devnet pair.
        $qadenatestscripts/setup_foundation_accounts.sh \
            --appsvr "$foundation_appsvr" --users "$foundation_users" --amount "$foundationamount"
        _appsvr_addr=$(qadenad_alias keys show "$foundation_appsvr" -a 2>/dev/null)
        _users_addr=$(qadenad_alias keys show "$foundation_users" -a 2>/dev/null)
        [ -n "$_appsvr_addr" ] && [ -n "$_users_addr" ] \
            || { echo "FAILED: could not resolve the foundation sponsor addresses"; exit 1; }
        export VERITAS_FUND_MODE=foundation-sponsored
        export VERITAS_FOUNDATION_APPSVR="$foundation_appsvr"
        step1_extra=(--deployment epdc --appsvr "$_appsvr_addr" --users "$_users_addr")
        step23_extra=(--deployment epdc)
    fi

    $veritasscripts/step_1.sh "${step1_extra[@]}" --count $count --provideramount $provideramount --signeramount $signeramount --createwalletsponsoramount $createwalletsponsoramount --createwalletsponsorname $createwalletsponsorname --pioneer $pioneer --treasurymnemonic $epdctreasurymnemonic --signermnemonic $signermnemonic --createwalletsponsormnemonic $createwalletsponsormnemonic --identityprovidermnemonic $identityprovidermnemonic --dsvsprovidermnemonic $dsvsprovidermnemonic --treasuryname $treasuryname --identityprovidername $identityprovidername --dsvsprovidername $dsvsprovidername --email $email --avalue $avalue --firstname $firstname --birthdate $birthdate --phone $phone --dsvsname $dsvsname

    if [ "$fund_mode" = "banksend" ]; then
        $qadenatestscripts/grant_from_treasury.sh $treasuryname 2000000qdn
        $qadenatestscripts/whitelist_bank_send.sh $treasuryname \
            "epdc deployment treasury: funds providers and users by direct bank send"
    else
        echo "-------------------------"
        echo "FOUNDATION: delegate grant authority and pre-grant every wallet"
        echo "-------------------------"
        _pregrant="$epdc_home/pregrant_addresses.json"
        [ -r "$_pregrant" ] || { echo "FAILED: no $_pregrant -- step_1 did not complete"; exit 1; }
        $qadenafoundationscripts/epdc_after_step_1.sh --pregrant "$_pregrant" \
            --foundation-appsvr "$foundation_appsvr"
    fi

    $veritasscripts/step_2.sh "${step23_extra[@]}"

    epdcidentityproposal_id=$(cat $qadenaproviderscripts/proposals/$identityprovidername.proposal_id)
    epdcdsvsproposal_id=$(cat $qadenaproviderscripts/proposals/$dsvsprovidername.proposal_id)
    for _spec in "$identityprovidername:$epdcidentityproposal_id" "$dsvsprovidername:$epdcdsvsproposal_id"; do
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

    if [ "$fund_mode" != "banksend" ]; then
        _pool="$epdc_home/pool_addresses.json"
        [ -r "$_pool" ] || { echo "FAILED: no $_pool -- step_3 did not complete"; exit 1; }
        $qadenafoundationscripts/epdc_after_step_3.sh --pool-addresses "$_pool" \
            --foundation-users "$foundation_users" \
            --foundation-appsvr "$foundation_appsvr"
    fi
fi  # end of the chain half

# ---------------------------------------------------------------------------------------------
# The contract half.  Skipped by --no-contracts.
# ---------------------------------------------------------------------------------------------
contract_address=""
if [ "$with_contracts" = "true" ]; then
    echo "-------------------------"
    echo "Building the epdc-register contract"
    echo "-------------------------"
    if [ "$rebuild" = "true" ] || [ ! -f "$epdcdir/artifacts/epdc_register.wasm" ]; then
        # optimizer.sh mounts "$(pwd)", so it must run FROM the contract directory.
        ( cd "$epdcdir" && ./optimizer.sh ) || { echo "FAILED: optimizer.sh could not build the contract"; exit 1; }
    else
        echo "artifacts/epdc_register.wasm exists -- skipping the build (pass --rebuild to force)"
    fi

    echo "-------------------------"
    echo "Creating the EPDC deployer/orchestrator wallets"
    echo "-------------------------"
    "$cli" setup-epdc || { echo "FAILED: epdc_cli.sh setup-epdc"; exit 1; }

    # UPLOAD AND INSTANTIATE ARE NOT IDEMPOTENT -- check the recorded contract is ON THIS CHAIN and
    # that EPDC CREATED IT before skipping deployment (setup_enf.sh documents both failure modes).
    existing=$("$cli" contract-addr 2>/dev/null | tail -1)
    if [ -n "$existing" ]; then
        creator=$(qadenad_alias query wasm contract "$existing" --output json 2>/dev/null | jq -r '.contract_info.creator // empty' 2>/dev/null)
        deployer=$(qadenad_alias keys show EPDC -a 2>/dev/null)
        if [ -z "$creator" ]; then
            echo "Recorded contract $existing is NOT on this chain -- redeploying (epdc_state.json is stale)"
            existing=""
        elif [ "$creator" != "$deployer" ]; then
            echo "Recorded contract $existing was created by $creator, not the EPDC deployer $deployer -- redeploying"
            existing=""
        fi
    fi
    if [ -n "$existing" ] && [ "$force_contracts" != "true" ]; then
        echo "Contract already deployed: $existing  (pass --force-contracts to replace it)"
        contract_address="$existing"
    else
        [ -n "$existing" ] && echo "--force-contracts: replacing the recorded contract $existing"
        "$cli" upload || { echo "FAILED: epdc_cli.sh upload"; exit 1; }
        "$cli" instantiate || { echo "FAILED: epdc_cli.sh instantiate"; exit 1; }
        contract_address=$("$cli" contract-addr 2>/dev/null | tail -1)
        [ -n "$contract_address" ] || { echo "FAILED: instantiate recorded no contract address"; exit 1; }
    fi

    echo "-------------------------"
    echo "Registering the demo attestor roster"
    echo "-------------------------"
    "$cli" register-attestors || { echo "FAILED: epdc_cli.sh register-attestors"; exit 1; }
fi

echo ""
echo "========================="
echo "setup complete"
echo "========================="
echo ""
echo "These go into the epdc API env (follow-the-money stacks/epdc/env-cloudflare.local, or .env for the"
echo "dev variant). They carry PRIVATE keys and the keyring passphrase -- never a committed env file."
echo ""

# A missing file prints a marker rather than dying under set -e at the last step (setup_enf.sh).
emit_key_var() {
    local var="$1" file="$2"
    if [ -f "$file" ]; then
        echo "$var='`cat $file`'"
    else
        echo "$var=<MISSING: no $file in $PWD>"
        echo "WARNING: $file not found in $PWD -- rerun from the directory the onboarding wrote it to" >&2
    fi
}
emit_key_var EPDC_DSVS_SRV_PRV_USERNAME "$dsvsprovidername-names.base64"
emit_key_var EPDC_DSVS_SRV_PRV_PRIVATE_KEY "$dsvsprovidername-keys.base64"
emit_key_var EPDC_DSVS_EPH_USERNAME "$dsvsname-names.base64"
emit_key_var EPDC_DSVS_EPH_PRIVATE_KEY "$dsvsname-keys.base64"
emit_key_var EPDC_DSVS_EPH_CREDENTIAL_USERNAME "$dsvsname-credential-names.base64"
emit_key_var EPDC_DSVS_EPH_CREDENTIAL_PRIVATE_KEY "$dsvsname-credential-keys.base64"
# Custodial payor signing: the api creates each payor's wallets (sponsored by this pool) and has the
# identity provider issue the email + phone credentials the enclave checks the signer against.
emit_key_var EPDC_IDENTITY_SRV_PRV_USERNAME "$identityprovidername-names.base64"
emit_key_var EPDC_IDENTITY_SRV_PRV_PRIVATE_KEY "$identityprovidername-keys.base64"
emit_key_var EPDC_CREATE_WALLET_SPONSOR_USERNAME "$createwalletsponsorname-names.base64"
emit_key_var EPDC_CREATE_WALLET_SPONSOR_PRIVATE_KEY "$createwalletsponsorname-keys.base64"
if [ -n "$contract_address" ]; then
    echo "EPDC_REGISTER_CONTRACT_ADDRESS=$contract_address"
    "$cli" attestor-keys
fi
echo "# the keys above are armored with the keyring passphrase, so the api must decrypt with it:"
echo "ARMOR_PASS_PHRASE=<the keyring passphrase>"
echo ""
echo "Then recreate the api and register the orchestrator wallets:"
echo "  docker compose -f stacks/epdc/compose-cloudflare.yml up -d --force-recreate --no-deps api"
echo "  make -C stacks/epdc setup-backend-if-needed"
