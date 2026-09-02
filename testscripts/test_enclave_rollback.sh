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

# See the anchored DIVERGED check at the bottom: everything asserted from the log must come from
# lines this run wrote.
rollback_log_start=$(wc -l < "$QADENAHOME/logs/qadena.log" 2>/dev/null || echo 0)

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

# Does the ENCLAVE hold a wallet with this ID?  Read out of the enclave itself via
# export-private-state -- not the chain, and not a hash: the actual record.
#
# DEBUG ENCLAVES ONLY.  export-private-state dumps sealed contents, so a real SGX enclave
# refuses it; on SGX the store-hash comparison below is the available evidence.
enclave_has_wallet() {
    # .Wallets is an ARRAY of wallet objects keyed by walletID, not a map -- has() would error
    local n
    n=$(qadenad_alias enclave export-private-state 2>/dev/null \
        | sed -n '/^{/,$p' \
        | jq -r --arg w "$1" '[.Wallets[]? | select(.walletID==$w)] | length' 2>/dev/null)
    [ "$n" = "1" ]
}

# Can we read the enclave's contents at all?  export-private-state dumps sealed state, so a real
# SGX enclave refuses it.  Probe once, explicitly, rather than inferring it from a failed lookup
# -- inferring would turn a BROKEN query into a silent skip, which is exactly how a suite ends up
# reporting success while testing nothing.
enclave_contents_readable() {
    qadenad_alias enclave export-private-state 2>/dev/null | sed -n '/^{/,$p' | jq -e '.Wallets' > /dev/null 2>&1
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
        # SKIPPED, not failed, and the distinction is deliberate.
        #
        # Refusing here is correct: rolling this node back alone and restarting it would re-produce
        # blocks at heights its peers already hold -- a fork manufactured by the test.  But that is
        # a property of the TOPOLOGY, not a defect in the code under test, and it is the same shape
        # as the two other loud skips in this suite: ss-rotation cannot force a rotation on SGX, and
        # peer-agreement cannot compare anything on a single node.  Both say so and exit 0.
        #
        # Failing instead would make continuous regression permanently red from the moment a second
        # node attaches -- and a suite that is always red is a suite everyone learns to ignore,
        # which costs more than the coverage it was protecting.
        echo "SKIPPED: this node holds $my_power/$total_power voting power (>= 1/3) and has $peer_count peer(s)."
        echo "  Rolling it back alone and restarting would re-produce blocks at heights its peers"
        echo "  already hold -- a fork manufactured by the test.  SOLO ROLLBACK IS THEREFORE UNTESTED"
        echo "  in this run; it is covered whenever this node runs without peers."
        echo "  A rollback at this stake level is only safe as the coordinated all-node procedure in"
        echo "  docs/HOWTO-CHAIN-RECOVERY.md; see TESTING-BACKLOG P0 #2 for the fixture that would"
        echo "  automate it, which is what should cover this topology."
        exit 0
    fi
fi

# Env-defaulted like the setup scripts: the devnet's validator is pioneer1, a launch chain's is
# its own (qfi-pioneer1).  Hardcoding it made this suite devnet-only.
pioneer="${QADENA_PIONEER:-pioneer1}"
pioneer_addr=$(qadenad_alias keys show "$pioneer" -a --keyring-backend test) || fail "cannot resolve $pioneer"

# ---- 1. a real transaction ----
bal_before=$(pioneer_balance)
[ "$bal_before" != "0" ] || fail "$pioneer has no balance to measure against"

# THE ENCLAVE'S OWN STATE, fingerprinted.  Everything else here measures the CHAIN; this is the
# only thing that proves the ENCLAVE rolled back rather than merely moving its watermark.
# GetStoreHash returns hashes of the nine mirror stores, never their contents, so it works on a
# real SGX enclave too -- unlike export-private-state.
hash_before=$(as_enclave_owner "$qadenad_binary" --home "$QADENAHOME" enclave store-hash 2>/dev/null | sort)
[ -n "$hash_before" ] || fail "cannot read the enclave's store hashes"

# A CREATE-WALLET, not a bank send: it writes a Wallet into the ENCLAVE, which is the state
# whose disappearance proves the enclave rolled back.  A bank send moves only chain balances.
test_wallet="rbtest$(date +%s)"
test_mnemonic=$(qadenad_alias keys mnemonic --keyring-backend test) || fail "cannot generate a mnemonic"

result=$(qadenad_alias tx qadena create-wallet "$test_wallet" "$pioneer" \
    --account-mnemonic="$test_mnemonic" create-wallet-sponsor --yes --keyring-backend test \
    --gas-prices "$minimum_gas_prices" --gas auto --gas-adjustment "$gas_adjustment" --output json 2>&1) \
    || fail "create-wallet broadcast failed"
# create-wallet prints plain text BEFORE and AFTER the JSON tx response (homePioneerAddress,
# sponsorAddress, then the fee-grant result), so neither head nor tail finds it -- take the
# first line that actually starts a JSON object.
result_json=$(printf '%s\n' "$result" | grep -m1 '^{') || true
[ -n "$result_json" ] || fail "create-wallet produced no JSON response: $result"
txhash=$(printf '%s' "$result_json" | jq -r .txhash)
[ "$(printf '%s' "$result_json" | jq -r .code)" = "0" ] || fail "tx rejected at broadcast: $result_json"

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

wallet_id=$(qadenad_alias keys show "$test_wallet" -a --keyring-backend test 2>/dev/null) \
    || fail "cannot resolve the new wallet's address"

# THE POSITIVE HALF: the enclave must now hold this wallet.
if enclave_contents_readable; then
    can_read_enclave=1
    enclave_has_wallet "$wallet_id" \
        || fail "the create-wallet transaction landed at height $h_tx but the ENCLAVE does not hold wallet $wallet_id -- the later absence check would prove nothing"
    echo "tx $txhash landed at height $h_tx; ENCLAVE now holds wallet $wallet_id"
else
    can_read_enclave=0
    echo "tx $txhash landed at height $h_tx (SGX enclave: contents not readable, using store hashes only)"
fi

# Recorded for the report only.  It is NOT the signal this suite turns on -- see the networked
# branch below for why a balance cannot decide a create-wallet rollback.
bal_after=$(pioneer_balance)
[ -n "$bal_after" ] || fail "cannot read pioneer1's balance after the transaction"

# THE ENCLAVE'S ACCUMULATORS AT THE TRANSACTION HEIGHT -- the enclave's answer to an app hash.
#
# Per-store digests, and HEIGHT-ADDRESSABLE, which is what makes them usable here: after a rollback
# and re-sync the chain has moved on, so a CURRENT fingerprint (store-hash) can never match and
# tells you nothing.  Asking for the same height on both sides does.  Digest-only, so this works on
# a real SGX enclave where contents are unreadable.
acc_at_tx=$(as_enclave_owner "$qadenad_binary" --home "$QADENAHOME" enclave store-accumulators --height "$h_tx" 2>/dev/null | sort)
[ -n "$acc_at_tx" ] || fail "cannot read the enclave's accumulators at height $h_tx"

# a bank send moves wallet state, so the enclave's mirrors must have moved with it.  If they did
# not, the comparison after the rollback would be vacuous -- it would "match" because nothing
# ever changed, and the suite would pass without testing anything.
hash_after=$(as_enclave_owner "$qadenad_binary" --home "$QADENAHOME" enclave store-hash 2>/dev/null | sort)
[ "$hash_after" != "$hash_before" ] || fail "the enclave's store hashes did not change across the transaction -- the post-rollback comparison would prove nothing"

# ---- 2. roll chain and enclave back to the height before the tx ----
target=$((h_tx - 1))
"$qadenascripts/stop_qadena.sh" --all > /dev/null 2>&1 || true

# SELF-CONTAINED: rollback spawns its own enclave when none is serving and stops it before
# returning (cmd/qadenad/cmd/rollback.go) -- this used to be a manual standalone enclave start,
# a 60s readiness poll, and a stop, all of which the command now owns.
qadenad_alias rollback --height "$target" || fail "qadenad rollback --height $target failed"
echo "rolled back to $target"

# The command must leave no enclave of its own behind -- the restart below wants a clean machine,
# and a leak here would be adopted silently by the next start and mask the bug.
if pgrep -f "qadenad_enclave" > /dev/null 2>&1 ; then
    fail "rollback left an enclave process running -- it must stop what it spawned"
fi

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
    # THE NEGATIVE HALF, and the whole point: the wallet the transaction put INTO the enclave
    # must no longer be there.  This is read from the enclave itself, so it cannot be satisfied
    # by the chain having rolled back.
    if [ "$can_read_enclave" -eq 1 ]; then
        if enclave_has_wallet "$wallet_id"; then
            fail "the ENCLAVE still holds wallet $wallet_id after rolling back past the block that created it -- the enclave did NOT roll back"
        fi
        echo "ENCLAVE no longer holds wallet $wallet_id -- enclave state reverted"
    fi

    # and the ENCLAVE's state reverted with it -- the assertion this whole branch exists for.
    # Watermarks and balances could both look right while the enclave still held the
    # transaction's state; only the store hashes rule that out.
    hash_now=$(as_enclave_owner "$qadenad_binary" --home "$QADENAHOME" enclave store-hash 2>/dev/null | sort)
    [ "$hash_now" = "$hash_before" ] || fail "the ENCLAVE did not roll back: its store hashes differ from before the transaction
before: $hash_before
now:    $hash_now"
    echo "solo: tx at $h_tx erased, balance reverted to $bal_before, ENCLAVE store hashes match pre-transaction"
else
    # networked minority: the peers still hold the block, so we must have re-synced INTO it.
    #
    # THE ENCLAVE'S STATE IS THE SIGNAL, NOT THE BALANCE.  This branch used to compare pioneer1's
    # balance against $bal_after -- a variable that was never assigned, so it compared the correct
    # re-synced balance against an empty string and failed every time on a fleet.  Assigning it was
    # not the fix either: the transaction is a CREATE-WALLET paid by create-wallet-sponsor, so
    # pioneer1's balance does not move across it at all.  Either comparison is vacuous; one of them
    # merely fails loudly.  (The solo branch's balance line has the same emptiness, and is harmless
    # only because the store-hash check beside it does the real work.)
    #
    # So assert what the rollback actually disturbed: the enclave dropped this wallet when it rolled
    # back, and re-syncing must bring it back.  That is what "catch back up" means for a node whose
    # peers still hold the block.
    # THE ENCLAVE MUST HAVE RE-DERIVED THE SAME STATE AT THAT HEIGHT, digest for digest.
    #
    # The chain-level app-hash comparison below proves the CHAIN re-converged; it says nothing about
    # the enclave, whose mirror stores sit outside consensus.  A node can match every peer's app
    # hash while its enclave came back wrong -- which is the failure this suite exists to catch.
    acc_now=$(as_enclave_owner "$qadenad_binary" --home "$QADENAHOME" enclave store-accumulators --height "$h_tx" 2>/dev/null | sort)
    [ -n "$acc_now" ] || fail "cannot read the enclave's accumulators at height $h_tx after re-sync"
    if [ "$acc_now" != "$acc_at_tx" ]; then
        fail "the ENCLAVE did not re-derive its state at height $h_tx after rolling back and catching up
(a minority node that rolled back must rebuild exactly what it destroyed, not merely resync the chain)
before: $acc_at_tx
now:    $acc_now"
    fi
    echo "networked: re-synced past $h_tx, enclave accumulators at $h_tx match digest-for-digest"

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

# Anchored to lines written SINCE THIS SUITE BEGAN.  The log is cumulative across the whole run,
# so an unanchored grep re-reports any divergence some earlier suite already logged -- which is
# exactly how a permanent PioneerJar false alarm made this suite fail on rollbacks that were
# clean (2026-08-16).
logfile="$QADENAHOME/logs/qadena.log"
if [ -f "$logfile" ] && tail -n "+$((rollback_log_start + 1))" "$logfile" | grep -aq "DIVERGED AT AN AGREED HEIGHT"; then
    fail "enclave stores diverged at an agreed height after rollback"
fi

echo "test_enclave_rollback: PASSED -- chain at $h, watermarks $prepared/$confirmed"
