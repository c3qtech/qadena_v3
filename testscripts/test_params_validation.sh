#!/bin/zsh
#
# Regression test for module param validation, on the path governance actually uses.
#
# WHAT THIS PROVES THAT A UNIT TEST CANNOT.  Params.Validate() is a pure function and is unit-tested
# in x/qadena/types/params_validate_test.go.  What those tests cannot show is whether anything CALLS
# it.  For a long time almost nothing did: Validate() returned nil unconditionally, only
# GenesisState.Validate() reached it, and MsgUpdateParams went straight to SetParams -- which
# marshals whatever it is handed.  So the runtime path, the one a governance proposal takes, had no
# validation at all.
#
# THE VALUE THAT MATTERS.  update_credential_min_blocks_between_updates is one of only two signed
# params.  Its loader defaulted only on == 0, so a NEGATIVE cool-down passed straight through, and
# checkUpdateLimits then asks
#
#	blockHeight - LastUpdateHeight < <negative>
#
# which is never true.  The credential-update rate limit is not shortened, it is switched OFF --
# permanently, silently, on a chain that otherwise looks healthy.  That is the case this suite
# reproduces end to end.
#
# WHY IT IS SAFE TO RUN REPEATEDLY.  MsgUpdateParams REPLACES the whole Params struct, so this
# script never hand-writes one: it reads the live params and submits them back verbatim, changing at
# most the single field under test.  The rejected proposal writes nothing by definition, and the
# accepted one writes back exactly what was already there.  Params are re-read and compared at the
# end, so a regression that DID mutate them fails here rather than somewhere later and stranger.
#
# Run AFTER testscripts/setup.sh.

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

set -e

function qadenad_alias { "$qadenabin/qadenad" --home "$QADENAHOME" "$@" }

fail() {
    echo "FAILED: $1"
    exit 1
}

live_params() {
    qadenad_alias query qadena params --output json 2>/dev/null | jq -S '.params'
}

# submit_params_proposal <params-json> <title> -- echoes the proposal's FINAL status.
#
# Reports rather than asserts: a proposal that passes its vote and then FAILS to execute is the
# expected outcome for the first case here, so each caller says which status it expects.
submit_params_proposal() {
    local params_json="$1" title="$2" file result tx_hash proposal_id prop_status i

    file="/tmp/qadena-params-proposal.json"
    jq -n --arg authority "$authority" --arg title "$title" --argjson params "$params_json" '{
        messages: [ {
            "@type": "/qadena.qadena.MsgUpdateParams",
            authority: $authority,
            params: $params
        } ],
        metadata: "ipfs://CID",
        deposit: "100000qdn",
        title: $title,
        summary: $title,
        expedited: true
    }' > "$file" || fail "could not write $file"

    result=$(qadenad_alias tx gov submit-proposal "$file" --from treasury -y --output json \
        --gas-prices $minimum_gas_prices --gas $gas_auto --gas-adjustment $gas_adjustment 2>/dev/null) \
        || fail "could not submit: $title"
    [ "$(echo "$result" | jq -r .code)" = "0" ] \
        || fail "$title proposal tx failed: $(echo "$result" | jq -r .raw_log)"

    tx_hash=$(echo "$result" | jq -r .txhash)
    qadenad_alias query wait-tx "$tx_hash" --timeout 30s > /dev/null || fail "$title tx did not land"

    proposal_id=$(qadenad_alias query tx "$tx_hash" --output json \
        | jq -r '.events[] | select(.type=="submit_proposal") | .attributes[] | select(.key=="proposal_id") | .value')
    [ -n "$proposal_id" ] || fail "could not read the proposal id for $title"

    $qadenatestscripts/gov_vote_from_treasury.sh "$proposal_id" yes > /dev/null \
        || fail "could not vote on proposal $proposal_id"

    # Budgeted for the REGULAR voting period, not the expedited one: gov v1 converts an expedited
    # proposal that misses its expedited tally into a regular one, votes carried over, so it still
    # resolves -- just later.
    i=0
    while [ $i -lt 130 ]; do
        prop_status=$(qadenad_alias query gov proposal "$proposal_id" --output json 2>/dev/null | jq -r '.proposal.status')
        case "$prop_status" in
            PROPOSAL_STATUS_PASSED|PROPOSAL_STATUS_FAILED|PROPOSAL_STATUS_REJECTED) break ;;
        esac
        sleep 3
        i=$((i + 1))
    done
    echo "$prop_status"
}

echo "========================="
echo "preflight"
echo "========================="
qadenad_alias status > /dev/null 2>&1 || fail "chain is not reachable -- start it first"
qadenad_alias keys show treasury -a --keyring-backend test > /dev/null 2>&1 \
    || fail "treasury not in the keyring -- run testscripts/setup.sh first"

authority=$(qadenad_alias query auth module-account gov --output json 2>/dev/null \
    | jq -r '.account.value.address // .account.base_account.address')
[ -n "$authority" ] && [ "$authority" != "null" ] || fail "could not resolve the gov module address"

original_params=$(live_params)
[ -n "$original_params" ] && [ "$original_params" != "null" ] || fail "could not read the module params"
echo "params read; cool-down is currently $(echo "$original_params" | jq -r '.update_credential_min_blocks_between_updates // "unset"')"

echo "========================="
echo "1. a negative update cool-down is REFUSED"
echo "========================="
# The whole point.  A negative here does not tighten or loosen the credential update rate limit --
# it removes it, because the comparison it feeds can never be true.  Before Params.Validate() was
# implemented AND wired into MsgUpdateParams, this proposal passed and took effect in silence.
bad_params=$(echo "$original_params" | jq '.update_credential_min_blocks_between_updates = "-1"')

prop_status=$(submit_params_proposal "$bad_params" "regression test: negative credential update cool-down")
[ "$prop_status" = "PROPOSAL_STATUS_FAILED" ] \
    || fail "a negative cool-down must FAIL execution, got $prop_status -- param validation is not wired into MsgUpdateParams"
echo "rejected at execution as expected"

# A failed proposal must not have written anything.  Checked rather than assumed: the failure could
# in principle come after SetParams rather than before it.
after_bad=$(live_params)
[ "$after_bad" = "$original_params" ] \
    || fail "the refused proposal still changed the params"
echo "params unchanged"

echo "========================="
echo "2. an unparseable threshold is REFUSED"
echo "========================="
# A second shape of the same class: a value that is not a coin at all.  It would otherwise fail far
# from here, inside ResolveThresholdToAttoUSD at scan time, refusing every transfer by a sender in
# that jurisdiction with nothing pointing back at the proposal that caused it.
bad_params=$(echo "$original_params" | jq '.suspicious_transaction_threshold = "not-a-coin"')

prop_status=$(submit_params_proposal "$bad_params" "regression test: unparseable suspicious threshold")
[ "$prop_status" = "PROPOSAL_STATUS_FAILED" ] \
    || fail "an unparseable threshold must FAIL execution, got $prop_status"
echo "rejected at execution as expected"

[ "$(live_params)" = "$original_params" ] || fail "the refused proposal still changed the params"
echo "params unchanged"

echo "========================="
echo "3. a VALID params update still passes"
echo "========================="
# The other half, and the one that catches over-strict validation.  Cases 1 and 2 would both pass
# just as well if Validate() rejected everything -- which would brick governance's ability to change
# any param at all.  Submitting the live params back verbatim proves the gate opens for good input.
prop_status=$(submit_params_proposal "$original_params" "regression test: unchanged params must still be accepted")
[ "$prop_status" = "PROPOSAL_STATUS_PASSED" ] \
    || fail "a valid params update must PASS, got $prop_status -- validation is rejecting legitimate input"
echo "accepted as expected"

# ... and it wrote back exactly what was there.  This is also what makes the suite idempotent.
final_params=$(live_params)
[ "$final_params" = "$original_params" ] \
    || { diff <(echo "$original_params") <(echo "$final_params") | head -10
         fail "a no-op params update changed the stored params"; }
echo "params round-tripped unchanged"

echo "========================="
echo "PARAM VALIDATION TESTS PASSED"
echo "========================="
