#!/bin/zsh
#
# End-to-end test of chain+enclave rollback.
#
# WHAT IT ASSERTS DEPENDS ON THE TOPOLOGY, because rolling one node back means opposite things
# on a solo chain and on a network -- and asserting the solo property against a network would
# report a confident failure for entirely correct behaviour:
#
#   solo (no peers)          Rolling back erases the transaction for good: nothing else holds
#                            those blocks.  Assert the balance REVERTS and the chain re-produces
#                            past the erased height.  This is chain recovery.
#
#   minority validator       The network kept producing while this node was down and still holds
#   (< 1/3 of power)         the block.  Rolling this node back cannot erase anything -- it
#                            re-syncs and the transaction COMES BACK.  Assert re-convergence:
#                            it catches up past the rollback point, the balance returns to its
#                            post-transaction value, and its app hash matches the peers'.  This
#                            is NODE recovery, and it is the .140 case from the 2026-08-09
#                            incident.
#
#   majority validator       REFUSED, deliberately.  Rolling back a node that holds the stake
#   (>= 1/3 of power)        needed for quorum and restarting it alone makes it re-produce new
#                            blocks at heights its peers already hold -- a fork, manufactured by
#                            the test.  A majority rollback is only safe as the coordinated
#                            all-node procedure in docs/HOWTO-CHAIN-RECOVERY.md, which a
#                            single-node script cannot orchestrate.  See TESTING-BACKLOG P0 #2.
#
# DELIBERATELY FAILS rather than skips when the chain is not running: a rollback bug is a fork
# bug, and a suite that silently skips reports success while testing nothing.
#
# Run AFTER setup_prerequisites.sh.  Restarts the node; leaves the chain running.

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

set -e

RPC="http://localhost:26657"

function qadenad_alias { "$qadenabin/qadenad" --home "$QADENAHOME" "$@" }

fail() {
    echo "FAIL(test_enclave_rollback): $1"
    exit 1
}

chain_height() {
    curl -s -m 3 "$RPC/status" 2>/dev/null | jq -r '.result.sync_info.latest_block_height // empty'
}

pioneer_balance() {
    qadenad_alias query bank balances "$pioneer_addr" --output json 2>/dev/null \
        | jq -r '[.balances[] | select(.denom=="aqdn") | .amount][0] // "0"'
}

app_hash_at() {
    curl -s -m 5 "$RPC/block?height=$1" 2>/dev/null | jq -r '.result.block.header.app_hash // empty'
}

enclave_watermark() {
    qadenad_alias enclave height 2>/dev/null | grep "$1" | awk '{print $2}'
}

[ -n "$(chain_height)" ] || fail "chain is not running -- this suite refuses to skip"

# ---- topology ----
peer_count=$(curl -s -m 5 "$RPC/net_info" | jq -r '.result.n_peers // "0"')
my_power=$(curl -s -m 5 "$RPC/status" | jq -r '.result.validator_info.voting_power // "0"')
total_power=$(curl -s -m 5 "$RPC/validators" | jq -r '[.result.validators[].voting_power | tonumber] | add // 0')

echo "topology: $peer_count peer(s), this node holds $my_power of $total_power voting power"

if [ "$peer_count" -gt 0 ] && [ "$total_power" -gt 0 ]; then
    # >= 1/3 is the threshold that matters: below it the network makes progress without us
    if [ $((my_power * 3)) -ge "$total_power" ]; then
        fail "this node holds $my_power/$total_power voting power (>= 1/3) and has $peer_count peer(s).
Rolling it back alone and restarting would re-produce blocks at heights its peers already hold --
a fork manufactured by the test.  A rollback at this stake level is only safe as the coordinated
all-node procedure in docs/HOWTO-CHAIN-RECOVERY.md; see TESTING-BACKLOG P0 #2 for the fixture
that would automate it."
    fi
fi

pioneer_addr=$(qadenad_alias keys show pioneer1 -a --keyring-backend test) || fail "cannot resolve pioneer1"

# ---- 1. a real transaction ----
bal_before=$(pioneer_balance)
[ "$bal_before" != "0" ] || fail "pioneer1 has no balance to measure against"

# THE ENCLAVE'S OWN STATE, fingerprinted.  Everything else here measures the CHAIN; this is the
# only thing that proves the ENCLAVE rolled back rather than merely moving its watermark.
# GetStoreHash returns hashes of the nine mirror stores, never their contents, so it works on a
# real SGX enclave too -- unlike export-private-state.
hash_before=$(qadenad_alias enclave store-hash 2>/dev/null | sort)
[ -n "$hash_before" ] || fail "cannot read the enclave's store hashes"

result=$(qadenad_alias tx bank send treasury "$pioneer_addr" 3qdn --yes --keyring-backend test \
    --gas-prices "$minimum_gas_prices" --gas auto --gas-adjustment "$gas_adjustment" --output json) \
    || fail "tx broadcast failed"
txhash=$(echo "$result" | jq -r .txhash)
[ "$(echo "$result" | jq -r .code)" = "0" ] || fail "tx rejected at broadcast: $result"

txfile=$(mktemp)
landed=0
for i in {1..30}; do
    if qadenad_alias query tx "$txhash" --output json > "$txfile" 2>/dev/null; then landed=1; break; fi
    sleep 2
done
[ $landed -eq 1 ] || fail "tx $txhash never landed"
[ "$(jq -r .code "$txfile")" = "0" ] || fail "tx failed on chain"
h_tx=$(jq -r .height "$txfile")
rm -f "$txfile"

bal_after=$(pioneer_balance)
[ "$bal_after" != "$bal_before" ] || fail "balance did not change after the send"
echo "tx $txhash landed at height $h_tx; balance $bal_before -> $bal_after"

# a bank send moves wallet state, so the enclave's mirrors must have moved with it.  If they did
# not, the comparison after the rollback would be vacuous -- it would "match" because nothing
# ever changed, and the suite would pass without testing anything.
hash_after=$(qadenad_alias enclave store-hash 2>/dev/null | sort)
[ "$hash_after" != "$hash_before" ] || fail "the enclave's store hashes did not change across the transaction -- the post-rollback comparison would prove nothing"

# ---- 2. roll chain and enclave back to the height before the tx ----
target=$((h_tx - 1))
"$qadenascripts/stop_qadena.sh" --all > /dev/null 2>&1 || true

# rollback needs the enclave running and qadenad stopped
if use_real_enclave "$qadenabin/qadenad_enclave" ; then
    "$qadenascripts/run_realenclave.sh" > /dev/null 2>&1 &
else
    "$qadenascripts/run_enclave.sh" > /dev/null 2>&1 &
fi
enclave_up=0
for i in {1..60}; do
    if qadenad_alias enclave check-enclave > /dev/null 2>&1; then enclave_up=1; break; fi
    sleep 1
done
[ $enclave_up -eq 1 ] || fail "enclave did not come up standalone"

qadenad_alias rollback --height "$target" || fail "qadenad rollback --height $target failed"
echo "rolled back to $target"

# ---- 3. restart and verify -- the assertion depends on the topology ----
"$qadenascripts/stop_qadena.sh" --all > /dev/null 2>&1 || true
"$qadenascripts/start_qadena.sh" > /dev/null 2>&1 || fail "start_qadena.sh failed"

resumed=0
for i in {1..150}; do
    h=$(chain_height)
    if [ -n "$h" ] && [ "$h" -gt "$h_tx" ]; then resumed=1; break; fi
    sleep 2
done
[ $resumed -eq 1 ] || fail "chain did not get past the rollback point $h_tx"

bal_now=$(pioneer_balance)

if [ "$peer_count" -eq 0 ]; then
    # solo: the transaction is gone for good
    [ "$bal_now" = "$bal_before" ] || fail "solo rollback did not revert the balance: before=$bal_before now=$bal_now"

    # and the ENCLAVE's state reverted with it -- the assertion this whole branch exists for.
    # Watermarks and balances could both look right while the enclave still held the
    # transaction's state; only the store hashes rule that out.
    hash_now=$(qadenad_alias enclave store-hash 2>/dev/null | sort)
    [ "$hash_now" = "$hash_before" ] || fail "the ENCLAVE did not roll back: its store hashes differ from before the transaction
before: $hash_before
now:    $hash_now"
    echo "solo: tx at $h_tx erased, balance reverted to $bal_before, ENCLAVE store hashes match pre-transaction"
else
    # networked minority: the peers still hold the block, so we must have re-synced INTO it
    [ "$bal_now" = "$bal_after" ] || fail "re-sync did not restore the transaction: expected $bal_after, got $bal_now
(a minority node that rolled back must catch back up to the network, not erase its history)"
    echo "networked: re-synced past $h_tx, transaction restored, balance back to $bal_after"

    # and our app hash at the rollback point must match what the peers published.
    #
    # NOT `... | while read`: a piped loop runs in a subshell, so a fail() inside it would exit
    # the subshell and the suite would carry on and PASS.  Redirect from a here-string instead,
    # which keeps the loop in this shell.  (test_peer_agreement.sh has the same shape for the
    # same reason.)
    mine=$(app_hash_at "$h_tx")
    [ -n "$mine" ] || fail "cannot read own app hash at $h_tx after re-sync"
    peer_ips=$(curl -s -m 5 "$RPC/net_info" | jq -r '.result.peers[]?.remote_ip')
    compared=0
    while read -r ip; do
        [ -n "$ip" ] || continue
        theirs=$(curl -s -m 5 "http://$ip:26657/block?height=$h_tx" 2>/dev/null | jq -r '.result.block.header.app_hash // empty')
        if [ -n "$theirs" ]; then
            [ "$theirs" = "$mine" ] || fail "app hash at $h_tx differs from peer $ip after re-sync -- $mine vs $theirs"
            compared=$((compared + 1))
        fi
    done <<< "$peer_ips"
    echo "app hash at $h_tx agrees with $compared reachable peer(s)"
fi

prepared=$(enclave_watermark preparedHeight)
confirmed=$(enclave_watermark confirmedHeight)
[ -n "$prepared" ] || fail "cannot read enclave watermarks"
[ "$prepared" = "$confirmed" ] || fail "enclave watermarks disagree after restart: prepared=$prepared confirmed=$confirmed"

logfile="$QADENAHOME/logs/qadena.log"
if [ -f "$logfile" ] && grep -a "DIVERGED AT AN AGREED HEIGHT" "$logfile" > /dev/null; then
    fail "enclave stores diverged at an agreed height after rollback"
fi

echo "test_enclave_rollback: PASSED -- chain at $h, watermarks $prepared/$confirmed"
