#!/bin/zsh
#
# Add a non-wallet party to the scanned-contract whitelist, by governance.
#
#   whitelist_bank_send.sh <key-name-or-address> [reason] [--code-id N]
#
# WHAT THIS DOES AND DOES NOT DO.  It does NOT exempt the address from AML scanning -- nothing does.
# Every account-to-account transfer is scanned, and a listed party's sends are measured, accumulate
# in the rolling window, and are reported when they cross a threshold, exactly like anyone else's.
# What listing grants is narrower: permission to take part in a bank send while holding no
# credential, and reports that name the address and its recorded reason instead of a person.
#
# WHY A DEPLOYMENT NEEDS IT.  Each deployment creates its OWN treasury (ekycph-treasury,
# enf-treasury, sec-treasury) and funds providers and users with `tx bank send`.  Those treasuries
# are not wallets and hold no credential, so an unlisted one is refused as unscannable and every
# funding send fails.
#
# Only the bootstrap `treasury` is seeded at genesis.  Each deployment adds its own, which is exactly
# why this is keyed state rather than a param: adding one entry leaves every other untouched, whereas
# a param update would have to restate them all and would silently drop any it omitted.
#
# --code-id PINS A WASM CONTRACT.  A contract's admin can migrate it to new code, so an entry that
# named only an address would carry its approval over to whatever that address runs next.  The chain
# rejects a contract listed without a code ID, and a non-contract listed with one, so the flag is
# required for contracts and must be omitted for plain accounts.
#
# Idempotent: an address that is already listed is left alone.  MsgAddScannedContractWhitelist
# rejects duplicates, so re-running without this check would fail a proposal on a correct chain.

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

set -e

function qadenad_alias { "$qadenabin/qadenad" --home "$QADENAHOME" "$@" }

fail() {
    echo "FAILED: $1"
    exit 1
}

target=""
reason=""
code_id="0"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --code-id) code_id="$2"; shift 2 ;;
        *)
            if [ -z "$target" ]; then target="$1"
            elif [ -z "$reason" ]; then reason="$1"
            else fail "unexpected argument: $1"
            fi
            shift
            ;;
    esac
done

reason="${reason:-deployment treasury: funds providers and users by direct bank send}"

[ -n "$target" ] || fail "usage: whitelist_bank_send.sh <key-name-or-address> [reason] [--code-id N]"

# accept either a keyring name or a bech32 address, so callers can pass whichever they hold
if [[ "$target" == qadena1* ]]; then
    address="$target"
else
    address=$(qadenad_alias keys show "$target" -a --keyring-backend test 2>/dev/null) \
        || fail "$target is neither a bech32 address nor a key in the keyring"
fi
[ -n "$address" ] || fail "could not resolve an address for $target"

echo "-------------------------"
echo "Adding $target ($address) to the scanned-contract whitelist (codeID $code_id)"
echo "-------------------------"

if qadenad_alias query qadena show-scanned-contract-whitelist "$address" > /dev/null 2>&1; then
    echo "$address is already on the scanned-contract whitelist, nothing to do"
    exit 0
fi

authority=$(qadenad_alias query auth module-account gov --output json 2>/dev/null \
    | jq -r '.account.value.address // .account.base_account.address')
[ -n "$authority" ] && [ "$authority" != "null" ] || fail "could not resolve the gov module address"

proposalfile="$qadenaproviderscripts/proposals/scanned-contract-$(echo "$address" | tail -c 9).gen.json"
mkdir -p "$qadenaproviderscripts/proposals"

jq -n --arg authority "$authority" --arg address "$address" --arg reason "$reason" \
      --argjson codeID "$code_id" '{
    messages: [ {
        "@type": "/qadena.qadena.MsgAddScannedContractWhitelist",
        authority: $authority,
        address: $address,
        codeID: $codeID,
        reason: $reason
    } ],
    metadata: "ipfs://CID",
    deposit: "100000qdn",
    title: "allow \($address) to take part in scanned bank sends",
    summary: $reason,
    expedited: true
}' > "$proposalfile" || fail "could not write $proposalfile"

result=$(qadenad_alias tx gov submit-proposal "$proposalfile" --from treasury -y --output json \
    --gas-prices $minimum_gas_prices --gas $gas_auto --gas-adjustment $gas_adjustment) \
    || fail "could not submit the whitelist proposal for $address"
[ "$(echo "$result" | jq -r .code)" = "0" ] \
    || fail "whitelist proposal tx failed: $(echo "$result" | jq -r .raw_log)"

tx_hash=$(echo "$result" | jq -r .txhash)
# confirm_tx, NOT a bare `query wait-tx`.  wait-tx SUBSCRIBES to a websocket event for the hash,
# so when the transaction is included BEFORE the subscription is established the event never
# arrives and it reports a timeout for a transaction that SUCCEEDED.  At ~1.5s blocks that race is
# routinely lost: observed in regression run 11, where this call failed while the tx sat committed
# at height 35977 with code 0.  confirm_tx polls `query tx` regardless of how the wait turned out,
# which is the whole reason it exists.
confirm_tx "$tx_hash" 30 || fail "whitelist proposal tx $tx_hash did not land"

proposal_id=$(qadenad_alias query tx "$tx_hash" --output json \
    | jq -r '.events[] | select(.type=="submit_proposal") | .attributes[] | select(.key=="proposal_id") | .value')
[ -n "$proposal_id" ] || fail "could not read the whitelist proposal id"
echo "whitelist proposal id: $proposal_id"

$qadenatestscripts/gov_vote_from_treasury.sh "$proposal_id" yes \
    || fail "could not vote on the whitelist proposal"
$qadenaproviderscripts/query_service_provider_proposal.sh "$proposal_id" --wait \
    || fail "whitelist proposal $proposal_id did not pass"

# a passed proposal is not the same as an applied one -- confirm the entry is really there, or the
# deployment carries on and fails later at provider funding, pointing at the wrong thing
qadenad_alias query qadena show-scanned-contract-whitelist "$address" > /dev/null 2>&1 \
    || fail "proposal $proposal_id passed but $address is still not on the scanned-contract whitelist"
echo "$address added to the scanned-contract whitelist"
