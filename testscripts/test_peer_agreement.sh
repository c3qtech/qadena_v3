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

# WHO the peers are still comes from net_info.  HOW to reach them can be overridden.
#
# The two are different questions and this script used to conflate them.  net_info is the right
# source for WHO: it lists the peers actually connected, which is the point -- a supplied list
# would check the nodes you believe exist and miss one that is connected and diverging, which is
# the fork this suite was written for.
#
# But it reported each peer's `remote_ip`, which is where the CONNECTION CAME FROM.  For a peer
# that dialled out through NAT that is the NAT's address, nothing serves 26657 there, and the
# check degrades to "cannot compare" for a peer that is perfectly healthy.  Measured 2026-09-08:
# pioneer2 at 13.213.217.124, connected and syncing, unverifiable.
#
#   --peer-rpc <moniker>=<url>   check that peer at <url> instead of its remote_ip
#   --rpc <url>                  this node's RPC (default http://localhost:26657)
#
# An override never ADDS a peer -- if the moniker is not in net_info it is not connected, and
# saying so is the honest answer.
typeset -A PEER_RPC
while [[ $# -gt 0 ]]; do
    case "$1" in
        --rpc)      RPC="$2"; shift 2 ;;
        --peer-rpc) PEER_RPC[${2%%=*}]="${2#*=}"; shift 2 ;;
        --help|-h)
            print -r -- "Usage: test_peer_agreement.sh [--rpc <url>] [--peer-rpc <moniker>=<url>]..."
            print -r -- "  Peers are discovered from this node's net_info; --peer-rpc only changes"
            print -r -- "  the address used to reach one, for peers behind NAT."
            exit 0 ;;
        *) print -u2 -- "unknown option: $1"; exit 1 ;;
    esac
done

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
    # An override for this moniker wins over the remote_ip; see --peer-rpc above.
    if [[ -n "${PEER_RPC[$moniker]:-}" ]]; then
        prpc="${PEER_RPC[$moniker]}"
    else
        prpc="http://$ip:26657"
    fi

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
# TWO DIFFERENT FAILURES, and only one of them is visible in an app hash.
#
# A block header carries the app hash of the PREVIOUS block's execution.  /status latest_app_hash is
# the header of the node's latest block, so for a node at height P it is the result of executing
# P-1 -- NOT of executing P.  Comparing it against block[P+1] compares two different heights and
# fails on a perfectly healthy chain; that mistake was in the first two versions of this suite.
#
#   (a) DIVERGED AND STILL RUNNING -- a partition, or two nodes on different chains.  Their app
#       hashes for the same height differ, so comparing like for like finds it.
#
#   (b) DIVERGED AND HALTED -- what actually happened here.  The peer committed the block it
#       disagreed on, then rejected the NEXT one because its header carried the other node's
#       result, and stopped.  Its own bad app hash never reaches a block header anywhere, so no
#       comparison of published state can see it.  The only external evidence is that it stopped
#       following the chain while believing it was caught up.
#
# So (a) is caught by comparison and (b) by the halt check, and both are failures.
divergence=0
halted=0
compared=0
skipped=0
while IFS='|' read -r moniker ip; do
    [ -n "$ip" ] || continue
    # An override for this moniker wins over the remote_ip; see --peer-rpc above.
    if [[ -n "${PEER_RPC[$moniker]:-}" ]]; then
        prpc="${PEER_RPC[$moniker]}"
    else
        prpc="http://$ip:26657"
    fi

    # `|| pstatus=""` IS WHAT KEEPS THIS SUITE ALIVE.  curl exits 7 when it cannot connect, and
    # under `set -e` a failing command substitution in an assignment TERMINATES THE SCRIPT -- here,
    # silently, mid-section.  nth_node_bringup.sh then sees a non-zero exit and prints "PEER
    # AGREEMENT FAILED ... That is a fork", so an UNREACHABLE peer was reported as a FORKED chain.
    # Measured 2026-09-08 against pioneer2 behind NAT: section 2 printed its header and nothing
    # else, and the bringup declared a fork that did not exist.  Section 1 had the guard; section 2
    # did not, which is why the same peer produced a clean message there and a fork verdict here.
    pstatus=$(curl -s -m 8 "$prpc/status" 2>/dev/null) || pstatus=""
    # NOT REACHED IS NOT THE SAME AS DISAGREED, and this is a FORK DETECTOR -- a false positive
    # here sends someone hunting a split that does not exist.  An empty body was handled; a
    # NON-EMPTY body that is not CometBFT status was not.  A load balancer or proxy in front of a
    # peer answers with HTML, curl succeeds, jq yields nulls, and the comparison then runs on
    # nothing.  Require the shape before believing anything it says.
    if [ -z "$pstatus" ] || [ -z "$(echo "$pstatus" | jq -r '.result.sync_info.latest_block_height // empty' 2>/dev/null)" ]; then
        echo "  $moniker: RPC unreachable or not a CometBFT status -- NOT compared"
        skipped=$(( skipped + 1 ))
        continue
    fi
    pheight=$(echo "$pstatus" | jq -r '.result.sync_info.latest_block_height')
    ptheirs=$(echo "$pstatus" | jq -r '.result.sync_info.latest_app_hash')
    pcatching=$(echo "$pstatus" | jq -r '.result.sync_info.catching_up')
    [ -n "$pheight" ] && [ "$pheight" != "null" ] || { echo "  $moniker: no height"; continue; }

    # LIKE FOR LIKE: the peer's latest app hash is the header of ITS block at pheight, so compare it
    # against this node's header for the SAME height.
    # Same guard: this one queries the LOCAL node, but a node that is restarting answers nothing
    # and the assignment would be just as fatal.
    mine=$(curl -s -m 8 "$RPC/block?height=$pheight" 2>/dev/null \
           | jq -r '.result.block.header.app_hash' 2>/dev/null) || mine=""

    if [ -z "$mine" ] || [ "$mine" = "null" ]; then
        echo "  $moniker: this node has no block at $pheight -- NOT compared"
        skipped=$(( skipped + 1 ))
    elif [ "$ptheirs" = "$mine" ]; then
        echo "  $moniker: MATCH at height $pheight  ${mine:0:32}"
        compared=$(( compared + 1 ))
    else
        echo "  $moniker: DIVERGED at height $pheight"
        echo "      peer      ($moniker): $ptheirs"
        echo "      this node ($local_moniker): $mine"
        divergence=1
        compared=$(( compared + 1 ))
    fi

    behind=$(( local_height - pheight ))
    if [ "$behind" -gt 50 ] && [ "$pcatching" = "false" ]; then
        echo "      HALTED: $behind blocks behind, catching_up=false"
        halted=1
    fi
done <<< "$peers"

echo ""
echo "  compared $compared peer(s); $skipped not compared"
# SAY WHAT WAS ACTUALLY MEASURED.  A verdict that does not name its evidence is how "cannot reach a
# peer" gets read as "the chain forked".
if [ "$compared" -eq 0 ]; then
    echo ""
    echo "========================="
    echo "NOTHING COMPARED -- NOT TESTED"
    echo "========================="
    echo "Every peer was unreachable or served no comparable block, so this suite proves nothing"
    echo "about agreement.  It is not a pass and it is not a fork.  If a peer sits behind NAT or a"
    echo "load balancer, give it an address that answers /status:"
    echo "    --peer-rpc <moniker>=<url>"
    exit 0
fi

if [ "$divergence" -ne 0 ]; then
    fail "peers published DIFFERENT app hashes for the same height -- the chain has FORKED and both
       sides are still running.  One block produced different state on different nodes."
fi

if [ "$halted" -ne 0 ]; then
    fail "a peer stopped following the chain while believing it is caught up.
       That is a rejected block, not lost connectivity -- and a forked peer looks EXACTLY like
       this, because the app hash it disagreed on never reaches any block header.  Check its
       log for 'wrong Block.Header.AppHash' or 'CONSENSUS FAILURE'.
       Note the chain keeps producing blocks regardless if the remaining validators hold more
       than 2/3 of the stake, so nothing else will report a problem."
fi

echo "========================="
echo "PEER AGREEMENT TESTS PASSED"
echo "========================="
