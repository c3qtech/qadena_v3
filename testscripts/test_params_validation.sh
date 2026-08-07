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

# STDERR, not stdout.  Several helpers below are called inside $( ), which captures stdout -- a
# failure message written there disappears into the variable and set -e then kills the script with
# nothing printed at all.  That is exactly how the first version of this suite failed: one second,
# no output, no clue.
# A PRIVATE TEMPORARY FILE, not a fixed name in /tmp.
#
# This used to write /tmp/qadena-params-proposal.json unconditionally.  /tmp is world-writable and
# STICKY, so once a run under a different user (root, on an SGX box) left that file behind, every
# later run as an ordinary user failed with "permission denied" on a path that has nothing to do
# with what is being tested -- and the suite reported a failure that looked like a chain problem.
# A fixed name in a shared directory is also the classic shape of a symlink attack.
proposal_file=$(mktemp -t qadena-params-proposal.XXXXXX) || { echo "could not create a temp file"; exit 1; }
trap 'rm -f "$proposal_file"' EXIT INT TERM

fail() {
    echo "FAILED: $1" >&2
    exit 1
}

live_params() {
    qadenad_alias query qadena params --output json 2>/dev/null | jq -S '.params'
}

# write_proposal <params-json> <title> -- builds the proposal file, echoes its path.
write_proposal() {
    local params_json="$1" title="$2" file="$proposal_file"
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
    echo "$file"
}

# submit_expecting_rejection <params-json> <title> <expected-text>
#
# INVALID PARAMS ARE REFUSED AT SUBMISSION, NOT AT EXECUTION, and that is worth knowing precisely.
# MsgUpdateParams.ValidateBasic() calls Params.Validate(), and gov's SubmitProposal runs
# ValidateBasic on every message before it creates the proposal, so a bad param never becomes a
# proposal at all: no deposit is taken, no voting period elapses, and the submitting transaction
# fails immediately carrying the validation message.
#
# The first version of this suite expected PROPOSAL_STATUS_FAILED, i.e. a proposal that passes its
# vote and then fails to execute.  That is what would happen if the ONLY check were the one in the
# msg server handler -- which is where this fix was first aimed before the ValidateBasic path was
# traced.  Asserting the real behaviour also pins it: if ValidateBasic ever stopped calling
# Validate(), this case fails rather than quietly degrading to the slower, deposit-burning path.
submit_expecting_rejection() {
    local params_json="$1" title="$2" expected="$3" file out

    file=$(write_proposal "$params_json" "$title")

    # 2>&1 because the rejection arrives as an rpc error on stderr, not as a tx result
    out=$(qadenad_alias tx gov submit-proposal "$file" --from treasury -y --output json \
        --gas-prices $minimum_gas_prices --gas $gas_auto --gas-adjustment $gas_adjustment 2>&1) && {
        # It was accepted.  If it also produced a tx that succeeded, validation did nothing at all.
        if [ "$(echo "$out" | jq -r '.code' 2>/dev/null)" = "0" ]; then
            fail "$title was ACCEPTED; invalid params must be refused"
        fi
    }

    echo "$out" | grep -q "$expected" \
        || { echo "$out" | head -3 >&2
             fail "$title was refused, but not for the expected reason (wanted text matching: $expected)"; }
}

# submit_expecting_pass <params-json> <title> -- submits, votes, and requires the proposal to PASS.
submit_expecting_pass() {
    local params_json="$1" title="$2" file result tx_hash proposal_id prop_status i

    file=$(write_proposal "$params_json" "$title")

    # STDOUT AND STDERR SEPARATED, never 2>&1.  --gas auto writes "gas estimate: N" to stderr, and
    # folding that into the captured output puts a non-JSON line in front of the response, so
    # `jq -r .code` fails on a transaction that actually SUCCEEDED -- reporting a broken submit and
    # a broken validator when neither is true.  The rejection helper above can use 2>&1 precisely
    # because it greps text rather than parsing JSON.
    local errfile
    errfile=$(mktemp)
    result=$(qadenad_alias tx gov submit-proposal "$file" --from treasury -y --output json \
        --gas-prices $minimum_gas_prices --gas $gas_auto --gas-adjustment $gas_adjustment 2>"$errfile") \
        || { head -3 "$errfile" >&2; rm -f "$errfile"; fail "could not submit: $title"; }
    if [ "$(echo "$result" | jq -r .code 2>/dev/null)" != "0" ]; then
        echo "$result" | head -3 >&2
        head -3 "$errfile" >&2
        rm -f "$errfile"
        fail "$title proposal tx failed"
    fi
    rm -f "$errfile"

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
    [ "$prop_status" = "PROPOSAL_STATUS_PASSED" ] \
        || fail "$title must PASS, got $prop_status -- validation is rejecting legitimate input"
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
#
# int64 params are proto-JSON encoded as STRINGS ("10000"), so the replacement is "-1", not -1.
# Writing a bare number produces a params object the message cannot unmarshal, which would fail this
# case for an entirely unrelated reason and look like a validation success.
bad_params=$(echo "$original_params" | jq '.update_credential_min_blocks_between_updates = "-1"')

submit_expecting_rejection "$bad_params" \
    "regression test: negative credential update cool-down" \
    "update_credential_min_blocks_between_updates must not be negative"
echo "refused at submission, naming the offending param"

# Nothing was written.  Checked rather than assumed: a refusal that still mutated state would be a
# worse bug than the one this suite is about.
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

submit_expecting_rejection "$bad_params" \
    "regression test: unparseable suspicious threshold" \
    "suspicious_transaction_threshold"
echo "refused at submission, naming the offending param"

[ "$(live_params)" = "$original_params" ] || fail "the refused proposal still changed the params"
echo "params unchanged"

echo "========================="
echo "3. a VALID params update still passes"
echo "========================="
# The other half, and the one that catches over-strict validation.  Cases 1 and 2 would both pass
# just as well if Validate() rejected everything -- which would brick governance's ability to change
# any param at all.  Submitting the live params back verbatim proves the gate opens for good input.
submit_expecting_pass "$original_params" "regression test: unchanged params must still be accepted"
echo "accepted and passed as expected"

# ... and it wrote back exactly what was there.  This is also what makes the suite idempotent.
final_params=$(live_params)
[ "$final_params" = "$original_params" ] \
    || { diff <(echo "$original_params") <(echo "$final_params") | head -10
         fail "a no-op params update changed the stored params"; }
echo "params round-tripped unchanged"

echo "========================="
echo "PARAM VALIDATION TESTS PASSED"
echo "========================="
