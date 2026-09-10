#!/bin/zsh

treasury=$1
providername=$2
json_proposal=$3
service_provider_type=$4
# NO pioneer1 FALLBACK.  A wrong pioneer here does not fail -- it goes into a GOVERNANCE
# PROPOSAL, registering the provider under a pioneer that may not exist (or worse, one that
# does).  In the sponsored flow this is always passed by setup_provider_base from
# variables.json, where step_1 derived it from the chain itself.
pioneer=${5:-${QADENA_PIONEER:-}}
[ -n "$pioneer" ] || {
    echo "no pioneer given (arg 5) and QADENA_PIONEER unset."
    echo "The devnet's is pioneer1; a launch chain names its own (e.g. qfi-pioneer1) --"
    echo "derive it:  qadenad query qadena list-interval-public-key-id | grep -B1 'nodeType: pioneer'"
    exit 1
}

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

if [ -z $providername ] || [ -z $json_proposal ] ; then
    echo "Usage: submit_service_provider_proposal.sh <treasury> <providername> <proposal_type> (e.g. add_service_provider_proposal, deactivate_service_provider_proposal) <service_provider_type> (optional:  e.g. identity, finance) <pioneer> (optional: defaults to \$QADENA_PIONEER or pioneer1)"
    exit 1
fi

# check if address already exists
# NO SECOND --keyring-backend HERE.  qadenad_alias already supplies the backend AND the keyring
# directory, and passing `test` again overrode both -- so with SEC's keys in
# $VERITAS_SEC_HOME/keyring this looked in the node's keyring instead and found nothing.  An empty
# address then flowed into the proposal as a blank field.
address=$(qadenad_alias keys show $providername --output json 2> /dev/null | jq -r '.address')
if [ -z $address ] ; then
    echo "Address not found: $providername"
    exit 1
fi

# if $qadenaproviderscripts/proposals does not exist, create it
if [ ! -d "$qadenaproviderscripts/proposals" ]; then
    mkdir "$qadenaproviderscripts/proposals"
fi


# modify json_proposal
# homePioneerID is substituted for the SAME reason nodeID is.  The template carries a literal
# `pioneer1` -- correct on the devnet, wrong on any chain whose genesis validator is named
# something else, and the generator used to copy it through untouched.  Nothing rejects it at
# proposal time: the registration passes governance and looks healthy for the life of the chain.
# It fails much later and somewhere else entirely -- sign-recover-key resolves the PROVIDER'S
# home pioneer to sign a recovery share, GetIntervalPublicKey misses, and the operator sees
# `key not found` naming neither the provider nor the pioneer.  And it is UNRECOVERABLE:
# AddServiceProvider refuses an existing nodeID (ErrServiceProviderAlreadyExists) and deactivate
# overwrites rather than deletes, so the name is burned with the wrong pioneer baked in.
jq --arg nodeid "$providername" --arg pioneer "$pioneer" \
   '.messages[0].nodeID = $nodeid | .messages[0].homePioneerID = $pioneer' \
   "$qadenaproviderscripts/templates/$json_proposal.json" > "$qadenaproviderscripts/proposals/$providername.gen.json"


# check if the proposal has pubKID set
pubKID=$(cat "$qadenaproviderscripts/proposals/$providername.gen.json" | jq -r '.messages[0].pubKID // empty')
echo "pubKID: $pubKID"
if [ -n "$pubKID" ] ; then
    echo "pubKID found in proposal, setting it to $address"
    jq --arg address "$address" '.messages[0].pubKID = $address' "$qadenaproviderscripts/proposals/$providername.gen.json" > "$qadenaproviderscripts/proposals/$providername-1.gen.json"
    mv "$qadenaproviderscripts/proposals/$providername-1.gen.json" "$qadenaproviderscripts/proposals/$providername.gen.json"
fi

# check if the proposal has serviceProviderType set
serviceProviderType=$(cat "$qadenaproviderscripts/proposals/$providername.gen.json" | jq -r '.messages[0].serviceProviderType // empty')
if [ -n "$serviceProviderType" ] ; then
    if [ -z $service_provider_type ] ; then
        echo "Error: serviceProviderType found in proposal but it was not provided"
        exit 10
    fi
    echo "serviceProviderType found in proposal, setting it to $service_provider_type"
    jq --arg service_provider_type "$service_provider_type" '.messages[0].serviceProviderType = $service_provider_type' "$qadenaproviderscripts/proposals/$providername.gen.json" > "$qadenaproviderscripts/proposals/$providername-1.gen.json"
    mv "$qadenaproviderscripts/proposals/$providername-1.gen.json" "$qadenaproviderscripts/proposals/$providername.gen.json"
fi

echo "-------------------------"
echo "Submit proposal"
echo "-------------------------"


# submit json_proposal
# WHO SUBMITS DEPENDS ON THE FUNDING MODEL.
#
# banksend: $treasury is sec-treasury, SEC's own funded key -- it signs and deposits directly.
#
# Sponsored: the chain demands a MINIMUM INITIAL DEPOSIT from the PROPOSER ("was (), need
# 12500000000000000000000aqdn") -- real tokens, which no fee grant can carry and SEC holds none
# of.  A provider can therefore never be the proposer.  The proposer is the FOUNDATION: the inner
# MsgSubmitProposal is built --generate-only --from the sponsor's address (no key needed), its
# balance pays the template's 100000qdn initial deposit, and SEC's admin execs it under the
# MsgSubmitProposal authz from sec_veritas_after_step_1.sh.  The proposal_id is read from the
# exec's events exactly as before -- authz re-emits the inner message's events.
# SIGNER-OPTIONAL, THE SAME WAY grant_as_foundation IS.  With VERITAS_SEC_ADMIN set (a real
# split deployment) the admin execs the submission under its authz.  Unset -- the single-keyring
# harness -- fall through to signing directly as $treasury, which is exactly what "worked in
# sponsored mode before": the harness holds the foundation key, so the direct signature succeeds
# and the deposit comes from the same balance either way.  The on-chain outcome is identical;
# only who signs differs.
if [ "${VERITAS_FUND_MODE:-}" = "foundation-sponsored" ] && [ -n "${VERITAS_SEC_ADMIN:-}" ]; then
    # THE TEMPLATE'S DEPOSIT IS THE SPONSOR'S WHOLE FLOAT.  100000qdn was sized for the retired
    # 2M sec-treasury; the sponsor holds exactly 100,000 and has paid fees from it, so the
    # submission died on "spendable balance 99999.99997... is smaller than 100000" (measured
    # 2026-09-06).  The chain's minimum INITIAL deposit is 12,500 (also measured); 20000 clears
    # it with margin and leaves the float intact for its real job.  Deposits are REFUNDED when
    # the proposal passes, and QFI's after_step_2 tops the total up to the full minimum anyway.
    jq '.deposit = "20000qdn"' "$qadenaproviderscripts/proposals/$providername.gen.json" \
        > "$qadenaproviderscripts/proposals/$providername-0.gen.json"
    mv "$qadenaproviderscripts/proposals/$providername-0.gen.json" "$qadenaproviderscripts/proposals/$providername.gen.json"
    _inner=$(mktemp)
    qadenad_alias tx gov submit-proposal "$qadenaproviderscripts/proposals/$providername.gen.json" \
        --from $treasury --generate-only > "$_inner" 2>/dev/null \
        || { echo "could not build the inner submit-proposal"; rm -f "$_inner"; exit 1; }
    result=$(qadenad_alias tx authz exec "$_inner" --from "$VERITAS_SEC_ADMIN" --fee-granter $treasury \
        -y --output json --gas-prices $minimum_gas_prices --gas auto --gas-adjustment $gas_adjustment)
    rm -f "$_inner"
else
    result=$(qadenad_alias tx gov submit-proposal "$qadenaproviderscripts/proposals/$providername.gen.json" --from $treasury -y --output json --gas-prices $minimum_gas_prices --gas auto --gas-adjustment $gas_adjustment)
fi
echo "Result: $result"
submit_hash=$(echo $result | jq -r .txhash)
# check if code is 0
if [ "$(echo $result | jq -r '.code // -1')" -ne 0 ]; then
    echo "Error: $(echo $result | jq -r .message)"
    exit 1
fi

echo "submit_hash: $submit_hash"
# wait for the proposal to be submitted
qadenad_alias query wait-tx $submit_hash --timeout 30s

# Get the proposal ID
proposal_id=$(qadenad_alias query tx $submit_hash --output json | jq -r '.events[] | select(.type=="submit_proposal") | .attributes[] | select(.key=="proposal_id") | .value')
echo "proposal_id: $proposal_id"

echo "-------------------------"
echo "Deposit into proposal"
echo "-------------------------"

# deposit into the proposal
if [ "${VERITAS_FUND_MODE:-}" = "foundation-sponsored" ]; then
    echo "sponsored mode: no ${DEPLOY_DISPLAY:-SEC}-side deposit -- QFI deposits in sec_veritas_after_step_2.sh"
    result='{"code":0,"txhash":""}'
else
result=$(qadenad_alias tx gov deposit $proposal_id 100000qdn --from $treasury -y --output json --gas-prices $minimum_gas_prices --gas auto --gas-adjustment $gas_adjustment)
fi
echo "Result: $result"
deposit_hash=$(echo $result | jq -r .txhash)
# check if code is 0
if [ "$(echo $result | jq -r '.code // -1')" -ne 0 ]; then
    echo "Error: $(echo $result | jq -r .message)"
    exit 1
fi
echo "deposit_hash: $deposit_hash"

# wait for the deposit to be submitted -- the sponsored-mode sentinel has no hash to wait on
if [ -n "$deposit_hash" ]; then
    result=$(qadenad_alias query wait-tx $deposit_hash --output json --timeout 30s)
    echo "Result: $result"
    if [ "$(echo $result | jq -r '.code // -1')" -ne 0 ]; then
        echo "Error: $(echo $result | jq -r '.raw_log // .message // "no output"')"
        exit 1
    fi
fi

# get deposit status
deposits=$(qadenad_alias query gov deposits $proposal_id --output json)
echo "Deposits: $deposits"

# get proposal status
proposal=$(qadenad_alias query gov proposal $proposal_id --output json)
echo "Proposal: $proposal"

# save proposal id
echo "$proposal_id" > $qadenaproviderscripts/proposals/$providername.proposal_id

