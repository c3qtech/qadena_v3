#!/bin/zsh
#
# Do this node's PEERS agree with it?
#
# WHY THIS EXISTS.  A two-validator chain forked on the first suspicious transaction report ever
# filed, and the regression reported 16 of 16 suites PASSED while it happened.  Every suite talks to
# localhost, so a second validator computing a different app hash -- and halting with
#
#     wrong Block.Header.AppHash.  Expected 8B5A7DF7..., got FFE85F5A...
#
# was entirely outside what the tests observed.  The chain kept producing blocks because the stake
# was lopsided: one validator held 99% of the power and finalised alone.  Had the split been even,
# the chain would have halted and been impossible to miss.  It was the asymmetry that hid it.
#
# The bug itself was non-deterministic encryption: reports are written into CONSENSUS state, and
# ecies.Encrypt draws a fresh ephemeral key and nonce from crypto/rand, so each validator's enclave
# produced different bytes for the same report.  See BEncryptDeterministic.
#
# WHAT THIS CHECKS.  For every peer this node knows about, compare the app hash at a height they have
# both passed.  Divergence means the peers executed the same block into different state -- a fork --
# and no amount of local assertion will reveal it.
#
# SKIPS CLEANLY on a single-node chain, since there is nothing to compare and a lone node is always
# self-consistent.  That is a real limitation rather than a passing grade, so it says so.

SCRIPT_DIR="${0:A:h}"
source "$SCRIPT_DIR/../scripts/setup_env.sh"

set -e

RPC="http://localhost:26657"

fail() {
    echo "FAILED: $1"
    exit 1
}

echo "========================="
echo "preflight"
echo "========================="
curl -s -m 5 "$RPC/status" > /dev/null 2>&1 || fail "local RPC $RPC is not answering"

local_height=$(curl -s -m 5 "$RPC/status" | jq -r '.result.sync_info.latest_block_height')
local_moniker=$(curl -s -m 5 "$RPC/status" | jq -r '.result.node_info.moniker')
echo "this node: $local_moniker at height $local_height"

# The peer's RPC is reached on its advertised IP.  A peer that does not expose 26657 cannot be
# checked, which is reported rather than silently skipped.
peers=$(curl -s -m 5 "$RPC/net_info" | jq -r '.result.peers[]? | "\(.node_info.moniker)|\(.remote_ip)"')

if [ -z "$peers" ]; then
    echo ""
    echo "========================="
    echo "NO PEERS -- NOTHING COMPARED"
    echo "========================="
    echo "This is a single-node chain, so consensus agreement cannot be tested here at all."
    echo "A lone validator always agrees with itself; the fork this suite exists to catch is only"
    echo "observable with a second node.  Treat this as 'not tested', not as 'passed'."
    exit 0
fi

echo "peers: $(echo "$peers" | wc -l | tr -d ' ')"

echo "========================="
echo "1. every peer is following the chain"
echo "========================="
checked=0
diverged=0

echo "$peers" | while IFS='|' read -r moniker ip; do
    [ -n "$ip" ] || continue
    prpc="http://$ip:26657"

    pstatus=$(curl -s -m 8 "$prpc/status" 2>/dev/null) || pstatus=""
    if [ -z "$pstatus" ]; then
        echo "  $moniker@$ip: RPC not reachable -- cannot compare (not counted as agreement)"
        continue
    fi

    pheight=$(echo "$pstatus" | jq -r '.result.sync_info.latest_block_height')
    echo "  $moniker@$ip: height $pheight"

    # A peer stuck far behind while claiming not to be catching up is the signature of a halted
    # node -- which is exactly what a fork looks like from the outside.
    pcatching=$(echo "$pstatus" | jq -r '.result.sync_info.catching_up')
    behind=$(( local_height - pheight ))
    if [ "$behind" -gt 50 ] && [ "$pcatching" = "false" ]; then
        echo "    WARNING: $behind blocks behind and not catching up -- it may have halted"
    fi
done

echo "========================="
echo "2. THE APP HASHES AGREE"
echo "========================="
# COMPARED AT A HEIGHT BOTH NODES HAVE, which is the whole difficulty.  A peer that forked has
# HALTED, so it is hundreds of blocks behind and simply has no block at this node's current height --
# asking for one there returns nothing and looks like a network problem.  The divergence is only
# visible at the last height they both reached, which is exactly where the fork happened.
divergence=0
while IFS='|' read -r moniker ip; do
    [ -n "$ip" ] || continue
    prpc="http://$ip:26657"

    pheight=$(curl -s -m 8 "$prpc/status" 2>/dev/null | jq -r '.result.sync_info.latest_block_height' 2>/dev/null)
    if [ -z "$pheight" ] || [ "$pheight" = "null" ]; then
        echo "  $moniker: RPC unreachable -- NOT compared"
        continue
    fi

    common=$local_height
    [ "$pheight" -lt "$common" ] && common=$pheight
    # a couple of blocks back, so neither node is mid-commit
    common=$(( common - 2 ))
    [ "$common" -gt 1 ] || { echo "  $moniker: no common height yet"; continue; }

    mine=$(curl -s -m 8 "$RPC/block?height=$common" | jq -r '.result.block.header.app_hash' 2>/dev/null)
    theirs=$(curl -s -m 8 "$prpc/block?height=$common" | jq -r '.result.block.header.app_hash' 2>/dev/null)

    if [ -z "$mine" ] || [ "$mine" = "null" ]; then
        echo "  $moniker: this node has no block at $common (pruned?) -- NOT compared"
        continue
    fi
    if [ -z "$theirs" ] || [ "$theirs" = "null" ]; then
        echo "  $moniker: peer has no block at $common -- NOT compared"
        continue
    fi

    if [ "$mine" = "$theirs" ]; then
        echo "  $moniker: MATCH at height $common  ${mine:0:32}"
    else
        echo "  $moniker: DIVERGED at height $common"
        echo "      this node ($local_moniker): $mine"
        echo "      peer      ($moniker): $theirs"
        divergence=1
    fi
done <<< "$peers"

if [ "$divergence" -ne 0 ]; then
    fail "peers computed DIFFERENT app hashes for the same block -- the chain has FORKED.
       This is a consensus bug, not a flaky test: one block produced different state on
       different nodes.  Every node-local assertion will still pass, which is why this
       suite exists."
fi

echo "========================="
echo "PEER AGREEMENT TESTS PASSED"
echo "========================="
