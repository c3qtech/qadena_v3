#!/bin/zsh
#
# setup_epdc.sh -- prepare a devnet chain for the e-PDC app-server, like setup_enf.sh does for ENF.
#
#   ./testscripts/setup_epdc.sh              # build (if needed), deployer, contract, attestors
#   ./testscripts/setup_epdc.sh --rebuild    # rebuild the wasm first
#   ./testscripts/setup_epdc.sh --force-contracts   # replace a recorded contract
#
# then, once the epdc stack is up (follow-the-money):
#   make -C stacks/epdc setup-backend-if-needed
#
# WHAT IT DOES, in the order setup_enf.sh's contract half does it:
#   1. build epdc-smart-contracts/artifacts/epdc_register.wasm (optimizer.sh) if it is missing
#   2. epdc_cli.sh setup-epdc   -- the EPDC deployer/orchestrator wallet (+ credential + ephemerals),
#                                  funded from treasury
#   3. upload + instantiate     -- SKIPPED when epdc_state.json names a contract that is on this chain
#                                  AND was created by EPDC (the same guard setup_enf.sh has, for the
#                                  same reason: deterministic wasm addresses mean a stale state file
#                                  can name a real contract that belongs to something else)
#   4. register the three demo attestors (OPERATOR / DRAWEE / DISINTERESTED) on the contract
#   5. print the lines the epdc API env needs
#
# WHAT IT DOES NOT DO, YET: onboard epdc's own DSVS service provider. setup_enf.sh does that for ENF
# through veritas_scripts/step_1..3 (governance proposals for enfidentitysrvprv / enfdsvssrvprv)
# and prints the SEC_DSVS_* key lines. Without it the epdc API's DSVS queue is nil, so issuance
# and certificates log "DSVS service provider wallet not configured" and carry on -- the register
# anchoring, which is what this script wires, does not depend on it.
#
# Needs the devnet prerequisites first (it checks): testscripts/setup.sh (identity provider +
# create-wallet sponsor) and testscripts/setup_foundation_accounts.sh.

set -e

SCRIPT_DIR="${0:A:h}"
source "$SCRIPT_DIR/../scripts/setup_env.sh"

epdcdir="$SCRIPT_DIR/../epdc-smart-contracts"
cli="$epdcdir/epdc_cli.sh"
rebuild="false"
force_contracts="false"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --rebuild)          rebuild="true"; shift ;;
        --force-contracts)  force_contracts="true"; shift ;;
        --help|-h)
            echo "Usage: $0 [--rebuild] [--force-contracts]"
            echo "  --rebuild          rebuild the wasm even if artifacts/epdc_register.wasm exists"
            echo "  --force-contracts  upload + instantiate a new contract even if one is recorded"
            exit 0 ;;
        *) echo "Unknown option: $1 (try --help)"; exit 1 ;;
    esac
done

# The keyring is the encrypted `file` backend on a current devnet, and every step below signs.
qadena_keyring_unlock

echo "========================="
echo "preflight"
echo "========================="
for k in treasury testidentitysrvprv create-wallet-sponsor foundation-appsvr; do
    qadenad_alias keys show "$k" > /dev/null 2>&1 || {
        echo "FAILED: '$k' is not in the keyring."
        echo "  Run the devnet prerequisites first:"
        echo "    ./testscripts/setup.sh"
        echo "    QADENA_KEYRING_BACKEND=file ./testscripts/setup_foundation_accounts.sh"
        exit 1
    }
done
[ "$(qadenad_alias query qadena list-jar-regulator --output json 2>/dev/null | jq -r '.jarRegulator | length' 2>/dev/null)" -gt 0 ] 2>/dev/null || {
    echo "FAILED: no jar regulator on chain -- the enclave is not initialised (see init.sh / run.sh)"; exit 1; }
echo "chain up, enclave initialised, prerequisites present"

echo "-------------------------"
echo "Building the epdc-register contract"
echo "-------------------------"
if [ "$rebuild" = "true" ] || [ ! -f "$epdcdir/artifacts/epdc_register.wasm" ]; then
    # optimizer.sh mounts "$(pwd)", so it must run FROM the contract directory; the subshell keeps
    # the cd from leaking.
    ( cd "$epdcdir" && ./optimizer.sh ) || { echo "FAILED: optimizer.sh could not build the contract"; exit 1; }
else
    echo "artifacts/epdc_register.wasm exists -- skipping the build (pass --rebuild to force)"
fi

echo "-------------------------"
echo "Creating the EPDC deployer/orchestrator wallets"
echo "-------------------------"
"$cli" setup-epdc || { echo "FAILED: epdc_cli.sh setup-epdc"; exit 1; }

# UPLOAD AND INSTANTIATE ARE NOT IDEMPOTENT: each produces a new code_id / contract address,
# orphaning whatever the app-server was registered with. So check the recorded one first -- that it
# is ON THIS CHAIN and that EPDC CREATED IT (setup_enf.sh documents both failure modes).
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
    echo "-------------------------"
    echo "Uploading and instantiating the contract"
    echo "-------------------------"
    "$cli" upload || { echo "FAILED: epdc_cli.sh upload"; exit 1; }
    "$cli" instantiate || { echo "FAILED: epdc_cli.sh instantiate"; exit 1; }
    contract_address=$("$cli" contract-addr 2>/dev/null | tail -1)
    [ -n "$contract_address" ] || { echo "FAILED: instantiate recorded no contract address"; exit 1; }
fi

echo "-------------------------"
echo "Registering the demo attestor roster"
echo "-------------------------"
"$cli" register-attestors || { echo "FAILED: epdc_cli.sh register-attestors"; exit 1; }

echo ""
echo "========================="
echo "chain setup complete"
echo "========================="
echo ""
echo "These go into the epdc API env (follow-the-money stacks/epdc/.env). They contain demo PRIVATE"
echo "keys and the keyring passphrase: .env, never a committed env file."
echo ""
echo "EPDC_REGISTER_CONTRACT_ADDRESS=$contract_address"
"$cli" attestor-keys
echo "# the orchestrator keys are armored with the keyring passphrase, so the API must decrypt with it:"
echo "ARMOR_PASS_PHRASE=<the keyring passphrase>"
echo ""
echo "Then restart the api and register the orchestrator wallets with it:"
echo "  make -C stacks/epdc start-dev          # picks up the new .env"
echo "  make -C stacks/epdc setup-backend-if-needed"
