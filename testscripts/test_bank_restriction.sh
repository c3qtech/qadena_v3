#!/bin/zsh
#
# Regression test for the bank send restriction.
#
# THE RULE: every account-to-account movement of value is AML-scanned, whichever module moves it.
# Before this existed the scan only covered MsgTransferFunds, so `tx bank send` was an unmeasured
# second route around it -- including around the eKYC gate, which made that gate decorative: a
# wallet refused a transfer for having no residency could send the same funds anyway.
#
# Only TWO outcomes now, and only one of them skips the scan:
#
#   module account either side  ->  allowed, unscanned (fees, staking, gov, the qadena escrow)
#   anything else               ->  SCANNED, always.  Refused if it cannot be scanned; reported if
#                                   it crosses a threshold.
#
# THERE IS NO LONGER AN EXEMPTION.  A bank-send whitelist used to sit between those two, holding the
# funding treasuries, and its entries were not scanned at all.  It existed only because a report
# could not name a party without a personal-info credential -- so an account that had none could not
# be reported, and was therefore not scanned.  Reports now carry a party kind and a contract-shaped
# descriptor, so such an account CAN be scanned and reported, and the exemption is gone.
#
# What replaced it is the SCANNED-CONTRACT WHITELIST: the same governance-managed keyed state, but
# it grants something much narrower.  A listed party may take part in a bank send while holding no
# credential, and reports naming it carry its address and recorded reason instead of a person.  Its
# sends are measured, accumulate in the window, and are reported exactly like anyone else's.  Case 6
# is the test of that distinction, and it is the reason this suite exists in its current form.
#
# Entries are PINNED to a wasm code ID, because a contract's admin can migrate it: an entry naming
# only an address would carry a benign escrow's approval over to whatever that address runs next.
# Cases 7 and 8 cover both halves of that check.
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

# A PRIVATE TEMPORARY FILE, not a fixed name in /tmp.
#
# This used to write /tmp/qadena-whitelist-proposal.json unconditionally.  /tmp is world-writable and
# STICKY, so once a run under a different user (root, on an SGX box) left that file behind, every
# later run as an ordinary user failed with "permission denied" on a path that has nothing to do
# with what is being tested -- and the suite reported a failure that looked like a chain problem.
# A fixed name in a shared directory is also the classic shape of a symlink attack.
proposal_file=$(mktemp -t qadena-whitelist-proposal.XXXXXX) || { echo "could not create a temp file"; exit 1; }
trap 'rm -f "$proposal_file"' EXIT INT TERM

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
echo "1. a listed non-wallet may send, and the send is SCANNED"
echo "========================="
# treasury is seeded into scannedContractWhitelistList at genesis.  It has to be: the setup scripts
# fund every other account this way before governance can run, and an unlisted party holding no
# credential is refused as unscannable -- so a chain whose list was empty could not be bootstrapped.
#
# Well under the threshold, so it passes.  That it passes is NOT the interesting part; case 6 proves
# it was scanned rather than waved through.
ann_before=$(bank_aqdn "$ann_addr")
code=$(send_result treasury "$ann_addr" "100qdn")
[ "$code" = "0" ] || fail "treasury is on the scanned-contract whitelist but its send failed with code $code"
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
# and an omission would silently drop it.
#
# Proposals are expedited (30s voting period in config.yml) so this costs about a minute rather
# than the 300s a normal proposal would take.
authority=$(qadenad_alias query auth module-account gov --output json 2>/dev/null \
    | jq -r '.account.value.address // .account.base_account.address')
[ -n "$authority" ] && [ "$authority" != "null" ] || fail "could not resolve the gov module address"

# submit_whitelist_proposal <msgtype> <address> <codeID> <reason> <title>
#
# Echoes the proposal's FINAL status.  A proposal that passes its vote and then fails to execute is
# a real and expected outcome here -- cases 7 and 8 depend on it -- so this reports the status
# rather than asserting success, and each caller says which status it expects.
submit_whitelist_proposal() {
    local msgtype="$1" address="$2" codeid="$3" reason="$4" title="$5" file result tx_hash proposal_id
    file="$proposal_file"

    # `codeID` and `reason` exist on the ADD message only -- MsgRemoveScannedContractWhitelist
    # carries just an authority and an address, and an unknown field makes the whole message
    # unparseable, so the proposal is rejected at submission with nothing to say which field was at
    # fault.
    jq -n --arg authority "$authority" --arg address "$address" --arg reason "$reason" \
          --argjson codeID "${codeid:-0}" --arg t "$msgtype" --arg title "$title" '{
        messages: [ ( { "@type": $t, authority: $authority, address: $address }
                      + (if $reason == "" then {} else { codeID: $codeID, reason: $reason } end) ) ],
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
    # 60s, and a RE-QUERY before giving up -- matching every other wait in this file, which this one
    # did not.  At 30s it was the only wait that could fail the suite on a slow block, and on a
    # loaded two-core box it did:
    #
    #     timed out waiting for transaction ... to be included in a block: internal logic error
    #
    # against a proposal that landed with code 0 a moment later.  "wait-tx timed out" and "the
    # transaction did not land" are different claims, and only the second is worth failing on.
    if ! qadenad_alias query wait-tx "$tx_hash" --timeout 60s > /dev/null 2>&1; then
        qadenad_alias query tx "$tx_hash" --output json > /dev/null 2>&1 \
            || fail "$title tx did not land"
    fi

    proposal_id=$(qadenad_alias query tx "$tx_hash" --output json \
        | jq -r '.events[] | select(.type=="submit_proposal") | .attributes[] | select(.key=="proposal_id") | .value')
    [ -n "$proposal_id" ] || fail "could not read the proposal id for $title"

    $qadenatestscripts/gov_vote_from_treasury.sh "$proposal_id" yes > /dev/null \
        || fail "could not vote on proposal $proposal_id"

    # Wait for the voting period to close.  Not query_service_provider_proposal.sh --wait: that
    # treats anything other than PASSED as a failure, and a FAILED execution is exactly what two of
    # these cases are asserting.
    # THE DEADLINE COMES FROM THE CHAIN, NOT FROM A CONSTANT.
    #
    # This used to poll 60 times at 2s -- a flat 120 seconds.  That comfortably covers the 30s
    # expedited_voting_period and is LESS THAN HALF the 300s regular voting_period, which made the
    # suite fail against a chain doing exactly the right thing:
    #
    # an expedited proposal whose threshold is not met inside its window is CONVERTED to a regular
    # one by the SDK -- ordinary behaviour, not a fault -- and it then needs the full voting period.
    # Observed 2026-08-19: three proposals in this same run kept expedited status and resolved in
    # 30s, one converted, and the poll gave up on it at 120s. It reached PROPOSAL_STATUS_FAILED --
    # precisely what the caller asserts -- about three minutes after the suite had already declared
    # a chain defect that did not exist.
    #
    # So the wait is sized from `voting_period` as the chain is actually configured. It follows a
    # config change instead of rotting against it, and the early `break` means a proposal that stays
    # expedited still returns in ~30s -- this costs nothing in the common case.
    local prop_status="" vp vp_secs max_wait i=0
    vp=$(qadenad_alias query gov params --output json 2>/dev/null \
        | jq -r '.params.voting_period // .voting_period // ""')
    # THE CHAIN ANSWERS IN GO DURATION FORMAT, NOT PLAIN SECONDS.  config.yml says `voting_period:
    # "300s"`, but `query gov params` renders it as "5m0s" -- so the obvious `${vp%s}` yields "5m0",
    # which is not a number.  Stripping the suffix and testing for digits therefore ALWAYS took the
    # fallback path: right answer here by luck, and silently wrong the moment the configured period
    # stops being five minutes.  Parse h/m/s properly instead.
    vp_secs=$(printf '%s' "$vp" | awk '{
        h=0; m=0; s=0
        if (match($0, /[0-9]+h/))                 { h = substr($0, RSTART, RLENGTH-1) + 0 }
        if (match($0, /[0-9]+m/))                 { m = substr($0, RSTART, RLENGTH-1) + 0 }
        if (match($0, /[0-9]+(\.[0-9]+)?s/))      { s = substr($0, RSTART, RLENGTH-1) + 0 }
        print int(h*3600 + m*60 + s)
    }')
    # A zero or unparseable answer falls back rather than collapsing the arithmetic and
    # reintroducing the original bug.
    case "$vp_secs" in (''|*[!0-9]*|0) vp_secs=300 ;; esac
    # +90s of margin: the tally runs in the block AFTER voting closes, and a busy chain can take a
    # few blocks to get there.
    max_wait=$(( vp_secs + 90 ))
    while [ $i -lt $(( max_wait / 2 )) ]; do
        prop_status=$(qadenad_alias query gov proposal "$proposal_id" --output json 2>/dev/null | jq -r '.proposal.status // .status // ""')
        case "$prop_status" in
            PROPOSAL_STATUS_PASSED|PROPOSAL_STATUS_FAILED|PROPOSAL_STATUS_REJECTED) break ;;
        esac
        sleep 2
        i=$((i + 1))
    done
    # Say WHY a wait ran out, so the next reader does not have to rediscover the conversion rule.
    case "$prop_status" in
        PROPOSAL_STATUS_PASSED|PROPOSAL_STATUS_FAILED|PROPOSAL_STATUS_REJECTED) ;;
        *) echo "  (proposal $proposal_id still '$prop_status' after ${max_wait}s -- voting_period is ${vp:-unknown})" >&2 ;;
    esac
    echo "$prop_status"
}

whitelist_status=$(submit_whitelist_proposal "/qadena.qadena.MsgAddScannedContractWhitelist" \
    "$plain_addr" 0 "regression test: temporary entry" "add $plain_acct to the scanned-contract whitelist")
[ "$whitelist_status" = "PROPOSAL_STATUS_PASSED" ] \
    || fail "adding $plain_acct should have passed, got $whitelist_status"

qadenad_alias query qadena show-scanned-contract-whitelist "$plain_addr" > /dev/null 2>&1 \
    || fail "the proposal passed but $plain_addr is not on the list"

ann_before=$(bank_aqdn "$ann_addr")
code=$(send_result "$plain_acct" "$ann_addr" "10qdn")
[ "$code" = "0" ] || fail "$plain_acct was listed but its send still failed with code $code"
ann_after=$(bank_aqdn "$ann_addr")
[ "$ann_after" != "$ann_before" ] || fail "the listed send reported success but moved nothing"
echo "listed send accepted"

whitelist_status=$(submit_whitelist_proposal "/qadena.qadena.MsgRemoveScannedContractWhitelist" \
    "$plain_addr" 0 "" "remove $plain_acct from the scanned-contract whitelist")
[ "$whitelist_status" = "PROPOSAL_STATUS_PASSED" ] \
    || fail "removing $plain_acct should have passed, got $whitelist_status"

ann_before=$(bank_aqdn "$ann_addr")
log=$(send_rawlog "$plain_acct" "$ann_addr" "10qdn")
echo "$log" | grep -q "code 1159" \
    || { echo "$log" | head -2; fail "after removal the send should be refused again with 1159, got the above"; }
ann_after=$(bank_aqdn "$ann_addr")
[ "$ann_after" = "$ann_before" ] || fail "a refused send still moved funds"
echo "refused again after removal"

# treasury was never mentioned in either proposal and must still work -- this is the whole reason
# the list is keyed state instead of a param
code=$(send_result treasury "$ann_addr" "1qdn")
[ "$code" = "0" ] \
    || fail "treasury's entry was lost while adding and removing a different one (code $code)"
echo "treasury's entry survived both proposals untouched"

echo "========================="
echo "6. a listed party is REPORTED, not exempt"
echo "========================="
# THE CENTRAL CLAIM OF THIS CHANGE, and the one thing the old whitelist made impossible to assert.
#
# Under that whitelist treasury was not scanned, so no treasury send -- of any size -- could ever
# produce a report.  Now it is scanned like anyone else, and a send at or above the reporting
# threshold has to file one.  If this test fails, the treasury is silently exempt again and the rest
# of this suite proves very little.
#
# The threshold is 10000usd by default and qdn is seeded at 0.01 USD, so 2,000,000qdn is $20,000 --
# clear of the chain default and of the per-jurisdiction overrides alike, without relying on which
# one the recipient's residency selects.
susp_before=$(qadenad_alias query qadena list-suspicious-transaction --count-total --output json 2>/dev/null \
    | jq -r '.pagination.total')
[ -n "$susp_before" ] || fail "could not read the suspicious transaction list"
echo "suspicious transactions before: $susp_before"

code=$(send_result treasury "$ann_addr" "2000000qdn")
[ "$code" = "0" ] \
    || fail "an over-threshold treasury send should be REPORTED and allowed, not refused (code $code)"

# EndBlock flushes new reports, so the count moves on the block after the send rather than in it
susp_after=""
i=0
while [ $i -lt 15 ]; do
    susp_after=$(qadenad_alias query qadena list-suspicious-transaction --count-total --output json 2>/dev/null \
        | jq -r '.pagination.total')
    [ "$susp_after" -gt "$susp_before" ] 2>/dev/null && break
    sleep 2
    i=$((i + 1))
done

[ "$susp_after" -gt "$susp_before" ] 2>/dev/null \
    || fail "an over-threshold treasury send filed NO report ($susp_before -> $susp_after); the treasury is exempt again"
echo "report filed: $susp_before -> $susp_after"

# ... and it names the treasury as a CONTRACT rather than inventing a person for it.  This is what
# the party kind is for: without it the report would have to carry a fabricated identity, which a
# regulator could not tell apart from a real one.
#
# --reverse --limit 1 asks the chain for the newest record, rather than sorting whatever the default
# page happened to contain.  The default --limit is 100, so once the chain held more than that this
# was sorting the FIRST hundred records and calling the hundredth "latest" -- reading a report from
# an earlier run, and asserting the party kind of a transaction this case did not make.
latest_kind=$(qadenad_alias query qadena list-suspicious-transaction --reverse --limit 1 --output json 2>/dev/null \
    | jq -r '.SuspiciousTransaction | last | .sourceKind // "SUSPICIOUS_PARTY_KIND_WALLET"')
[ "$latest_kind" = "SUSPICIOUS_PARTY_KIND_CONTRACT" ] \
    || fail "the report should name the treasury as a CONTRACT party, got $latest_kind"
echo "reported with sourceKind CONTRACT"

echo "========================="
echo "7. a non-contract cannot be pinned to a code ID"
echo "========================="
# Half of the pinning check.  A plain account listed WITH a code ID pins against something that will
# never be checked, so the entry would claim a guarantee it does not have.  Rejected at execution,
# where a reviewer can still see it, rather than surfacing much later as an unexplained refusal.
whitelist_status=$(submit_whitelist_proposal "/qadena.qadena.MsgAddScannedContractWhitelist" \
    "$plain_addr" 7 "regression test: bogus code id on a plain account" \
    "pin $plain_acct to a code ID it does not have")
[ "$whitelist_status" = "PROPOSAL_STATUS_FAILED" ] \
    || fail "listing a plain account with codeID 7 should FAIL execution, got $whitelist_status"

qadenad_alias query qadena show-scanned-contract-whitelist "$plain_addr" > /dev/null 2>&1 \
    && fail "the proposal failed but $plain_addr was listed anyway"
echo "rejected, and nothing was written"

echo "========================="
echo "8. a wasm contract MUST be pinned"
echo "========================="
# The other half, and the one that matters for security.  An unpinned contract entry would survive a
# migration: get a benign escrow approved, then migrate it into a drain and keep the approval.
wasm_file="$qadenatestdata/hackatom.wasm"
if [ ! -f "$wasm_file" ]; then
    fail "missing $wasm_file -- this case cannot be skipped silently, it is the migration guard"
fi

store_out=$(qadenad_alias tx wasm store "$wasm_file" --from treasury --yes --output json \
    "${gas_flags[@]}" 2>/dev/null) || fail "could not store the test contract"
store_hash=$(echo "$store_out" | jq -r '.txhash')
qadenad_alias query wait-tx "$store_hash" --timeout 60s > /dev/null 2>&1 || true
[ "$(qadenad_alias query tx "$store_hash" --output json 2>/dev/null | jq -r '.code')" = "0" ] \
    || fail "storing the test contract failed"

#
# --reverse --limit 1 asks the chain for the NEWEST code, rather than sorting the first page.
# list-code paginates at 100 by default, and this suite stores a contract on every run, so once the
# chain passed a hundred codes both this and the second store below read code_id 100 forever --
# and case 10, which requires the second store to produce a NEW id, failed with
#
#     FAILED: the second store did not produce a new code id (got 100, had 100)
#
# naming a store that had worked perfectly well.
wasm_code_id=$(qadenad_alias query wasm list-code --reverse --limit 1 --output json 2>/dev/null \
    | jq -r '.code_infos[0].code_id')
[ -n "$wasm_code_id" ] && [ "$wasm_code_id" != "null" ] || fail "no code id after store"

label="bankscan-pin-$(date +%s | tail -c 7)"
init=$(jq -nc --arg v "$(addr_of treasury)" --arg b "$ann_addr" '{verifier:$v,beneficiary:$b}')
inst_out=$(qadenad_alias tx wasm instantiate "$wasm_code_id" "$init" \
    --admin "$(addr_of treasury)" --label "$label" --from treasury --yes --output json \
    "${gas_flags[@]}" 2>/dev/null) || fail "could not instantiate the test contract"
inst_hash=$(echo "$inst_out" | jq -r '.txhash')
qadenad_alias query wait-tx "$inst_hash" --timeout 60s > /dev/null 2>&1 || true
[ "$(qadenad_alias query tx "$inst_hash" --output json 2>/dev/null | jq -r '.code')" = "0" ] \
    || fail "instantiating the test contract failed"

contract_addr=$(qadenad_alias query wasm list-contract-by-code "$wasm_code_id" --reverse --limit 1 --output json 2>/dev/null \
    | jq -r '.contracts[0]')
[ -n "$contract_addr" ] && [ "$contract_addr" != "null" ] || fail "could not resolve the contract address"
echo "contract $contract_addr at code id $wasm_code_id"

# codeID 0 on a real contract == unpinned == the migration hole.  Must be refused.
whitelist_status=$(submit_whitelist_proposal "/qadena.qadena.MsgAddScannedContractWhitelist" \
    "$contract_addr" 0 "regression test: unpinned contract" \
    "list $contract_addr without pinning its code")
[ "$whitelist_status" = "PROPOSAL_STATUS_FAILED" ] \
    || fail "listing a wasm contract with codeID 0 should FAIL execution, got $whitelist_status"

qadenad_alias query qadena show-scanned-contract-whitelist "$contract_addr" > /dev/null 2>&1 \
    && fail "the unpinned proposal failed but $contract_addr was listed anyway"
echo "unpinned contract refused"

# ... and the same contract pinned to its ACTUAL code id is accepted, so the check rejects the
# mistake rather than rejecting contracts in general
whitelist_status=$(submit_whitelist_proposal "/qadena.qadena.MsgAddScannedContractWhitelist" \
    "$contract_addr" "$wasm_code_id" "regression test: correctly pinned contract" \
    "list $contract_addr pinned to code $wasm_code_id")
[ "$whitelist_status" = "PROPOSAL_STATUS_PASSED" ] \
    || fail "listing the contract pinned to codeID $wasm_code_id should have passed, got $whitelist_status"

pinned=$(qadenad_alias query qadena show-scanned-contract-whitelist "$contract_addr" --output json 2>/dev/null \
    | jq -r '.scannedContractWhitelist.codeID')
[ "$pinned" = "$wasm_code_id" ] \
    || fail "the entry should be pinned to codeID $wasm_code_id, got $pinned"
echo "correctly pinned contract accepted, entry records codeID $pinned"

echo "========================="
echo "9. onboarding: a listed sender may pay an address with no identity -- and only a listed sender"
echo "========================="
# THE BOOTSTRAP CASE, and the narrowest loosening in this change.
#
# A treasury's whole purpose is funding accounts that do not have identities yet: a fresh key is
# funded, and only then acquires a wallet and a credential.  Requiring the recipient to be
# identifiable would refuse the first send on a fresh chain and make the chain unbootstrappable --
# which is exactly what happened when this was first written the other way round.
#
# The pair of assertions is the point.  Allowing it for a whitelisted sender while still refusing it
# for an ordinary wallet is what keeps this from reopening the gap for user-to-user sends; testing
# only the first half would pass just as well if the recipient gate had been removed outright.
fresh_acct="bankscan-fresh-$(date +%s | tail -c 7)"
qadenad_alias keys add "$fresh_acct" --keyring-backend test > /dev/null 2>&1 \
    || fail "could not create $fresh_acct"
fresh_addr=$(addr_of "$fresh_acct")

# No wallet, no credential -- nothing on chain knows who this is.
#
# Checked by OUTPUT, not exit code: show-wallet prints "err ... not found" and still exits 0, so
# `show-wallet >/dev/null && fail` reads a missing wallet as a present one and fails the case that
# is actually set up correctly.
qadenad_alias query qadena show-wallet "$fresh_addr" 2>&1 | grep -q "not found" \
    || fail "$fresh_acct was supposed to be a brand new key with no wallet"

code=$(send_result treasury "$fresh_addr" "50qdn")
[ "$code" = "0" ] \
    || fail "a listed sender must be able to fund an address with no identity (code $code); this is what bootstrap depends on"
[ -n "$(bank_aqdn "$fresh_addr")" ] || fail "the onboarding send reported success but moved nothing"
echo "treasury -> unidentified address accepted"

# ... and the same send from an ordinary credentialed wallet is still refused.  al holds a
# personal-info credential, so the sender side is fine; it is the recipient that cannot be named,
# and outside the onboarding case that is still fatal.
# Measured on the RECIPIENT, not the sender.  A refused send still lands in a block and still costs
# the sender gas, so al's balance moves either way -- asserting on it fails a correct refusal and
# would have passed had the send gone through for less than the fee.  Every other case here checks
# the recipient for the same reason.
fresh_before=$(bank_aqdn "$fresh_addr")
log=$(send_rawlog al "$fresh_addr" "5qdn")
echo "$log" | grep -q "code 1159" \
    || { echo "$log" | head -2; fail "a WALLET paying an unidentified address must still be refused with 1159, got the above"; }
[ "$(bank_aqdn "$fresh_addr")" = "$fresh_before" ] || fail "a refused send still moved funds"
echo "al -> unidentified address still refused (1159); the exception is scoped to listed senders"

echo "========================="
echo "10. migrating a listed contract REVOKES its entry"
echo "========================="
# THE CASE PINNING EXISTS FOR, and the only one that exercises the re-check on the send path rather
# than at proposal time.
#
# Cases 7 and 8 prove governance cannot approve a badly-pinned entry.  Neither touches what happens
# AFTER approval -- and that is the actual attack: get a benign contract whitelisted, then use the
# admin key to migrate it to different code and keep the approval.  The entry is re-verified on
# every send precisely so a migration voids it instead of inheriting it.
#
# contract_addr is the one case 8 whitelisted, pinned to $wasm_code_id, with treasury as admin.

# First prove the pin is VALID right now, so the refusal after migrating cannot be blamed on the
# send having been broken all along.
ann_before=$(bank_aqdn "$ann_addr")
code=$(send_result al "$contract_addr" "1qdn")
[ "$code" = "0" ] \
    || fail "al -> correctly-pinned contract should be allowed before any migration (code $code)"
echo "send to the correctly-pinned contract accepted"

# A SECOND code id, from the same wasm.  Identical code is fine and actually sharpens the test: the
# entry must be voided because the code ID it was approved under changed, not because the new code
# is detectably different.
store_out=$(qadenad_alias tx wasm store "$wasm_file" --from treasury --yes --output json \
    "${gas_flags[@]}" 2>/dev/null) || fail "could not store the second copy of the test contract"
store_hash=$(echo "$store_out" | jq -r '.txhash')
qadenad_alias query wait-tx "$store_hash" --timeout 60s > /dev/null 2>&1 || true
[ "$(qadenad_alias query tx "$store_hash" --output json 2>/dev/null | jq -r '.code')" = "0" ] \
    || fail "storing the second copy failed"

new_code_id=$(qadenad_alias query wasm list-code --reverse --limit 1 --output json 2>/dev/null \
    | jq -r '.code_infos[0].code_id')
[ -n "$new_code_id" ] && [ "$new_code_id" != "$wasm_code_id" ] \
    || fail "the second store did not produce a new code id (got $new_code_id, had $wasm_code_id)"
echo "second code id: $new_code_id"

# hackatom's MigrateMsg takes a verifier in the build used here, but has been {} in others.  Try the
# documented shape first and fall back once -- and FAIL LOUDLY if neither works, rather than
# skipping, because a silent skip here would leave the migration guard untested while reporting
# success.
migrate_ok=false
for migrate_msg in "$(jq -nc --arg v "$(addr_of treasury)" '{verifier:$v}')" '{}'; do
    mig_out=$(qadenad_alias tx wasm migrate "$contract_addr" "$new_code_id" "$migrate_msg" \
        --from treasury --yes --output json "${gas_flags[@]}" 2>/dev/null) || continue
    mig_hash=$(echo "$mig_out" | jq -r '.txhash')
    [ -n "$mig_hash" ] && [ "$mig_hash" != "null" ] || continue
    qadenad_alias query wait-tx "$mig_hash" --timeout 60s > /dev/null 2>&1 || true
    if [ "$(qadenad_alias query tx "$mig_hash" --output json 2>/dev/null | jq -r '.code')" = "0" ]; then
        migrate_ok=true
        echo "migrated with $migrate_msg"
        break
    fi
done
[ "$migrate_ok" = "true" ] \
    || fail "could not migrate $contract_addr to code $new_code_id; the migration guard is UNTESTED"

# the contract really is running the new code now
live_code_id=$(qadenad_alias query wasm contract "$contract_addr" --output json 2>/dev/null \
    | jq -r '.contract_info.code_id')
[ "$live_code_id" = "$new_code_id" ] \
    || fail "after migrating, the contract reports code $live_code_id, expected $new_code_id"

# The stored entry must be UNCHANGED -- governance approved a specific code, and a migration must not
# quietly re-point the approval at whatever is running now.
pinned=$(qadenad_alias query qadena show-scanned-contract-whitelist "$contract_addr" --output json 2>/dev/null \
    | jq -r '.scannedContractWhitelist.codeID')
[ "$pinned" = "$wasm_code_id" ] \
    || fail "the whitelist entry followed the migration ($wasm_code_id -> $pinned); the pin is meaningless"
echo "entry still pinned to the approved code $pinned while the contract runs $live_code_id"

# ... and the send is now refused, with the code that says WHY.  1162, not 1159: the party is still
# approved, it is the code that changed, and conflating the two would hide exactly this attack.
#
# Checked as the transaction's ABCI CODE, not by grepping the log for "code 1162" the way the 1159
# cases above do.  The two errors travel differently and only one of them prints its number:
#
#   1159  raised inside the ENCLAVE and returned over gRPC, so it reaches the chain as the text
#         "codespace qadena code 1159: ...", embedded in the log.  The number is in the message.
#   1162  raised chain-side by errorsmod.Wrapf, so the log carries only its description while the
#         registered code travels as the tx's real ABCI code.  Grepping for "code 1162" finds
#         nothing even when the refusal is exactly right -- which is what happened here.
#
# The code is the stricter check of the two in any case: it cannot be satisfied by wording.
contract_before=$(bank_aqdn "$contract_addr")
code=$(send_result al "$contract_addr" "1qdn")
[ "$code" = "1162" ] \
    || { echo "raw log: $(send_rawlog al "$contract_addr" "1qdn" | head -1)"
         fail "a send to a migrated contract must be refused with ABCI code 1162, got code $code"; }
[ "$(bank_aqdn "$contract_addr")" = "$contract_before" ] || fail "a refused send still moved funds"
echo "send to the migrated contract refused (qadena code 1162), nothing moved"

echo "========================="
echo "BANK RESTRICTION TESTS PASSED"
echo "========================="
