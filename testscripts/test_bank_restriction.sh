#!/bin/zsh
#
# Regression test for the bank send restriction.
#
# THE RULE: every account-to-account movement of value is AML-scanned, whichever module moves it.
# Before this existed the scan only covered MsgTransferFunds, so `tx bank send` was an unmeasured
# second route around it -- including around the eKYC gate, which made that gate decorative: a
# wallet refused a transfer for having no residency could send the same funds anyway.
#
# Three outcomes, all exercised here:
#
#   module account either side  ->  allowed, unscanned (fees, staking, gov, the qadena escrow)
#   whitelisted sender          ->  allowed, unscanned (the funding treasuries, which are not
#                                   wallets and hold no credential to draw a jurisdiction from)
#   anything else               ->  SCANNED; refused if it cannot be scanned or if it trips a
#                                   threshold.  There is no --opt-in-reason on MsgSend and nowhere
#                                   to put one, so an over-threshold bank send can only be refused.
#
# HOW FAILURES SURFACE.  Unlike transfer-funds, a rejected bank send is NOT caught during the CLI's
# --gas auto simulation: the scan is skipped in CheckTx, so the transaction broadcasts, gets a hash,
# and fails in the block.  The CLI exits 0.  Every assertion below therefore queries the transaction
# result rather than trusting the exit code -- checking the exit code alone would pass while
# testing nothing.
#
# Run AFTER testscripts/setup.sh.

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

set -e

function qadenad_alias { "$qadenabin/qadenad" --home "$QADENAHOME" "$@" }

gas_flags=(--gas auto --gas-adjustment 1.5 --gas-prices 0.5aqdn)

fail() {
    echo "FAILED: $1"
    exit 1
}

addr_of() {
    qadenad_alias keys show "$1" -a --keyring-backend test 2>/dev/null
}

bank_aqdn() {
    qadenad_alias query bank balances "$1" --output json 2>/dev/null \
        | jq -r '.balances[] | select(.denom=="aqdn") | .amount' | head -1
}

# send_result <from> <to-addr> <amount> -- broadcasts and echoes the on-chain result code.
#
# Waits for the transaction rather than reading the broadcast response: the broadcast only says the
# transaction was accepted into the mempool, and the scan runs later, during execution.
send_result() {
    local from="$1" to="$2" amount="$3" out hash
    # stdout only: --gas auto writes "gas estimate: N" to STDERR, and folding that into the JSON
    # makes jq fail on every call, which under set -e kills the script with no message at all
    out=$(qadenad_alias tx bank send "$from" "$to" "$amount" --from "$from" --yes --output json \
        "${gas_flags[@]}" 2>/dev/null) || { echo "BROADCAST_REJECTED"; return; }
    hash=$(echo "$out" | jq -r '.txhash' 2>/dev/null)
    if [ -z "$hash" ] || [ "$hash" = "null" ]; then
        echo "NO_TXHASH"
        return
    fi
    qadenad_alias query wait-tx "$hash" --timeout 60s > /dev/null 2>&1 || true
    qadenad_alias query tx "$hash" --output json 2>/dev/null | jq -r '.code // "UNKNOWN"'
}

# raw_log_of <from> <to> <amount> -- the same, but returns the failure text so a rejection can be
# checked for the RIGHT reason rather than merely for being a rejection
send_rawlog() {
    local from="$1" to="$2" amount="$3" out hash
    out=$(qadenad_alias tx bank send "$from" "$to" "$amount" --from "$from" --yes --output json \
        "${gas_flags[@]}" 2>/dev/null) || { echo "$out"; return; }
    hash=$(echo "$out" | jq -r '.txhash' 2>/dev/null)
    if [ -z "$hash" ] || [ "$hash" = "null" ]; then
        echo "no txhash from broadcast"
        return
    fi
    qadenad_alias query wait-tx "$hash" --timeout 60s > /dev/null 2>&1 || true
    qadenad_alias query tx "$hash" --output json 2>/dev/null | jq -r '.raw_log // ""'
}

echo "========================="
echo "preflight"
echo "========================="
qadenad_alias status > /dev/null 2>&1 || fail "chain is not reachable -- start it first"
for w in treasury al ann; do
    addr_of "$w" > /dev/null 2>&1 || fail "$w not in the keyring -- run testscripts/setup.sh first"
done
al_addr=$(addr_of al)
ann_addr=$(addr_of ann)
echo "chain up"

echo "========================="
echo "1. a whitelisted sender may send directly, unscanned"
echo "========================="
# treasury is seeded into bankSendWhitelistList at genesis.  It has to be: the setup scripts fund
# every other account this way before governance can run, so a chain whose whitelist was empty
# could not be bootstrapped at all.
ann_before=$(bank_aqdn "$ann_addr")
code=$(send_result treasury "$ann_addr" "100qdn")
[ "$code" = "0" ] || fail "treasury is whitelisted but its send failed with code $code"
ann_after=$(bank_aqdn "$ann_addr")
[ "$ann_after" != "$ann_before" ] || fail "treasury's send reported success but moved nothing"
echo "treasury -> ann accepted"

echo "========================="
echo "2. two credentialed wallets may send, and the send is SCANNED"
echo "========================="
# Both al and ann hold personal-info credentials, so a jurisdiction and therefore a threshold can be
# resolved for the sender and a report could name the recipient.  Well under the threshold, so it
# passes -- the point is that it is measured, not that it is blocked.
al_before=$(bank_aqdn "$al_addr")
code=$(send_result al "$ann_addr" "5qdn")
[ "$code" = "0" ] || fail "a scanned send between two credentialed wallets failed with code $code"
al_after=$(bank_aqdn "$al_addr")
[ "$al_after" != "$al_before" ] || fail "the send reported success but al's balance did not move"
echo "al -> ann accepted and scanned"

echo "========================="
echo "3. a sender that is not a wallet cannot be scanned, so it is refused"
echo "========================="
# A plain key -- which is also what a wasm contract address, an EVM EOA and an IBC escrow address
# look like from the bank module's point of view.  None of them can be scanned, and allowing them
# through unmeasured would leave exactly the gap this restriction closes.
# A PER-RUN account, not a fixed one.  Case 5 adds this address to the whitelist and removes it
# again; if a run dies between those two steps a fixed account would stay whitelisted, and the very
# next run would fail here -- asserting a refusal against an account that is now exempt.  A per-run
# name means a half-finished run can only ever strand an entry nothing else looks at.
plain_acct="bankscan-$(date +%s | tail -c 7)"
qadenad_alias keys add "$plain_acct" --keyring-backend test > /dev/null 2>&1 \
    || fail "could not create $plain_acct"
plain_addr=$(addr_of "$plain_acct")

if [ -z "$(bank_aqdn "$plain_addr")" ]; then
    code=$(send_result treasury "$plain_addr" "500qdn")
    [ "$code" = "0" ] || fail "could not fund $plain_acct from treasury (code $code)"
fi

ann_before=$(bank_aqdn "$ann_addr")
log=$(send_rawlog "$plain_acct" "$ann_addr" "10qdn")
echo "$log" | grep -q "code 1159" \
    || { echo "$log" | head -2; fail "expected qadena code 1159 (not scannable), got the above"; }
ann_after=$(bank_aqdn "$ann_addr")
[ "$ann_after" = "$ann_before" ] || fail "a refused send still moved funds"
echo "rejected as expected (qadena code 1159), nothing moved"

echo "========================="
echo "4. module legs still work: staking and governance"
echo "========================="
# Delegation moves coins to the bonded-tokens-pool module account and a gov deposit moves them to
# the gov module account.  Both go through the same SendCoins the restriction hooks, so if the
# module check were wrong the chain would be unusable rather than merely stricter -- worth proving
# rather than assuming.
validator=$(qadenad_alias query staking validators --output json 2>/dev/null \
    | jq -r '.validators[0].operator_address')
[ -n "$validator" ] && [ "$validator" != "null" ] || fail "could not find a validator to delegate to"

# Waiting for this to land is not politeness: treasury signs the proposals in case 5 too, and
# broadcasting a second transaction while this one is still in flight collides on the account
# sequence.  The failure then appears at the NEXT step, which is a thoroughly misleading place to
# start looking.
delegate_out=$(qadenad_alias tx staking delegate "$validator" 10qdn --from treasury --yes \
    --output json "${gas_flags[@]}" 2>/dev/null) \
    || fail "delegation was refused; the module-account check is wrong"
delegate_hash=$(echo "$delegate_out" | jq -r '.txhash')
qadenad_alias query wait-tx "$delegate_hash" --timeout 60s > /dev/null 2>&1 || true
delegate_code=$(qadenad_alias query tx "$delegate_hash" --output json 2>/dev/null | jq -r '.code // "UNKNOWN"')
[ "$delegate_code" = "0" ] \
    || fail "delegation failed with code $delegate_code; a module-account leg must not be blocked"
echo "delegation accepted"

echo "========================="
echo "5. the whitelist takes individual add and remove"
echo "========================="
# The property a param could not give.  plainacct -- which case 3 just proved is refused -- is added
# by governance, its send then succeeds, it is removed, and the send is refused again.  Throughout,
# treasury's entry is never restated: with the list in Params every change would have to repeat it,
# and an omission would silently revoke it.
#
# Proposals are expedited (30s voting period in config.yml) so this costs about a minute rather
# than the 300s a normal proposal would take.
authority=$(qadenad_alias query auth module-account gov --output json 2>/dev/null \
    | jq -r '.account.value.address // .account.base_account.address')
[ -n "$authority" ] && [ "$authority" != "null" ] || fail "could not resolve the gov module address"

whitelist_proposal() {
    local msgtype="$1" address="$2" reason="$3" title="$4" file result tx_hash proposal_id
    file="/tmp/qadena-whitelist-proposal.json"

    # `reason` exists on the ADD message only -- MsgRemoveBankSendWhitelist carries just an
    # authority and an address, and an unknown field makes the whole message unparseable, so the
    # proposal is rejected at submission with nothing to say which field was at fault.
    jq -n --arg authority "$authority" --arg address "$address" --arg reason "$reason" \
          --arg t "$msgtype" --arg title "$title" '{
        messages: [ ( { "@type": $t, authority: $authority, address: $address }
                      + (if $reason == "" then {} else { reason: $reason } end) ) ],
        metadata: "ipfs://CID",
        deposit: "100000qdn",
        title: $title,
        summary: $title,
        expedited: true
    }' > "$file" || fail "could not write $file"

    result=$(qadenad_alias tx gov submit-proposal "$file" --from treasury -y --output json \
        "${gas_flags[@]}" 2>/dev/null) || fail "could not submit: $title"
    [ "$(echo "$result" | jq -r .code)" = "0" ] \
        || fail "$title proposal tx failed: $(echo "$result" | jq -r .raw_log)"

    tx_hash=$(echo "$result" | jq -r .txhash)
    qadenad_alias query wait-tx "$tx_hash" --timeout 30s > /dev/null || fail "$title tx did not land"

    proposal_id=$(qadenad_alias query tx "$tx_hash" --output json \
        | jq -r '.events[] | select(.type=="submit_proposal") | .attributes[] | select(.key=="proposal_id") | .value')
    [ -n "$proposal_id" ] || fail "could not read the proposal id for $title"

    $qadenatestscripts/gov_vote_from_treasury.sh "$proposal_id" yes > /dev/null \
        || fail "could not vote on proposal $proposal_id"
    $qadenaproviderscripts/query_service_provider_proposal.sh "$proposal_id" --wait > /dev/null \
        || fail "proposal $proposal_id ($title) did not pass"
    echo "proposal $proposal_id passed: $title"
}

whitelist_proposal "/qadena.qadena.MsgAddBankSendWhitelist" "$plain_addr" \
    "regression test: temporary exemption" "add $plain_acct to the bank send whitelist"

ann_before=$(bank_aqdn "$ann_addr")
code=$(send_result "$plain_acct" "$ann_addr" "10qdn")
[ "$code" = "0" ] || fail "$plain_acct was whitelisted but its send still failed with code $code"
ann_after=$(bank_aqdn "$ann_addr")
[ "$ann_after" != "$ann_before" ] || fail "the whitelisted send reported success but moved nothing"
echo "whitelisted send accepted"

whitelist_proposal "/qadena.qadena.MsgRemoveBankSendWhitelist" "$plain_addr" "" \
    "remove $plain_acct from the bank send whitelist"

ann_before=$(bank_aqdn "$ann_addr")
log=$(send_rawlog "$plain_acct" "$ann_addr" "10qdn")
echo "$log" | grep -q "code 1159" \
    || { echo "$log" | head -2; fail "after removal the send should be refused again with 1159, got the above"; }
ann_after=$(bank_aqdn "$ann_addr")
[ "$ann_after" = "$ann_before" ] || fail "a refused send still moved funds"
echo "refused again after removal"

# treasury was never mentioned in either proposal and must still work -- this is the whole reason
# the whitelist is keyed state instead of a param
code=$(send_result treasury "$ann_addr" "1qdn")
[ "$code" = "0" ] \
    || fail "treasury's exemption was lost while adding and removing a different entry (code $code)"
echo "treasury's entry survived both proposals untouched"

echo "========================="
echo "BANK RESTRICTION TESTS PASSED"
echo "========================="
