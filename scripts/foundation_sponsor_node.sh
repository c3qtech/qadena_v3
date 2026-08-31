#!/bin/zsh
#
# THE FOUNDATION SPONSORS A JOINING NODE, so the node holds no QDN and needs no treasury.
#
# Run this on a box holding the foundation key, after the operator runs
#   add_full_node.sh --foundation-sponsored
# which mints the pioneer key and prints its address.
#
# WHAT A NODE ACTUALLY SPENDS -- FOR ITS WHOLE LIFE, NOT JUST THE JOIN
#
#   Joining (`qadenad enclave sync-enclave`) broadcasts three messages:
#       /qadena.qadena.MsgPioneerAddPublicKey
#       /qadena.qadena.MsgPioneerUpdateIntervalPublicKeyID
#       /qadena.qadena.MsgPioneerUpdatePioneerJar
#
#   But a RUNNING node keeps broadcasting.  UpdateHeight runs per block, and calls
#   updateSSIntervalKey (enclave.go:3606), which emits:
#       /qadena.qadena.MsgPioneerAddPublicKey
#       /qadena.qadena.MsgPioneerUpdateIntervalPublicKeyID
#       /qadena.qadena.MsgPioneerUpdatePublicKey        <-- the SS RE-SHARE
#   and InitEnclave additionally emits:
#       /qadena.qadena.MsgPioneerUpdateJarRegulator
#
#   SO A JOIN-ONLY GRANT IS A TRAP.  The node joins, runs, and then -- when its first SS rotation
#   comes due -- cannot pay for MsgPioneerUpdatePublicKey.  It stops re-sharing secret-share keys
#   while continuing to look healthy.  On this chain the SS set is consensus-relevant, so a node
#   that silently stops participating is not a cosmetic failure.
#
#   THAT IS ALSO WHY THE DEFAULT GRANT DOES NOT EXPIRE.  A 30-day expiry would cut SS rotation off
#   after 30 days, which is the same trap with a delay.  Ongoing cost is bounded by a PERIODIC
#   BUDGET instead: a per-period limit that refills, indefinitely.  That is the shape the agency
#   toll-free design uses, and it is the right one for a cost that recurs forever.
#
#   `--join-only` gives the narrow, expiring, three-message grant, for a node that will be funded
#   normally afterwards.
#
#   THE SELF-BOND IS FUNDED, NOT SPONSORED, and the distinction is the whole point.  --self-bond
#   SENDS QDN to the node; it does not fee-grant a stake.  On this chain QDN originates only from
#   the foundation, so an operator's stake necessarily came from there -- refusing to send it does
#   not create skin in the game, it just makes validators impossible.
#
#   What preserves skin in the game is that a TRANSFER is final: once sent, the tokens are the
#   operator's, they are what gets bonded, and slashing burns THEM.  The foundation keeps no
#   exposure.  That is exactly unlike a fee grant, where the foundation goes on paying for every
#   message forever -- which is why fees are granted and the bond is transferred.  An earlier
#   version of this note refused the self-bond outright on slashing grounds; that argument was
#   about ongoing exposure and does not reach a one-off transfer.
#
# WHY authz, NOT THE FOUNDATION KEY ON EVERY BOX
#
#   A fee grant is signed by its GRANTER.  grant_as_foundation (scripts/setup_env.sh) lets a
#   delegate sign on the foundation's behalf: the foundation authorises an admin key ONCE for
#   /cosmos.feegrant.v1beta1.MsgGrantAllowance and that key then wraps each grant in a MsgExec.
#   Set QADENA_NODE_ADMIN to use that path; unset, this signs directly and needs the granter's key.

SCRIPT_DIR="${0:A:h}"
source "$SCRIPT_DIR/setup_env.sh"

set -e

node_addr=""
granter="${QADENA_FOUNDATION_NODES:-foundation-nodes}"
expiration=""
spend_limit=""
self_bond=""
join_only="false"
# 30 days of budget, refilled every 30 days, forever.  Sized well above a node's actual burn: SS
# rotation is a handful of messages per interval, not per block.
period="2592000"
period_limit="1000qdn"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --node)        node_addr="$2"; shift 2 ;;
        --granter)     granter="$2"; shift 2 ;;
        --expiration)  expiration="$2"; shift 2 ;;
        --spend-limit) spend_limit="$2"; shift 2 ;;
        --join-only)   join_only="true"; shift ;;
        --self-bond)   self_bond="$2"; shift 2 ;;
        --period)      period="$2"; shift 2 ;;
        --period-limit) period_limit="$2"; shift 2 ;;
        --help)
            echo "Usage: $0 --node <pioneer-address> [--granter <key>] [--expiration <unix>] [--spend-limit <amt>]"
            echo ""
            echo "  --node         the pioneer address add_full_node.sh printed.  Required."
            echo "  --granter      foundation key that pays (default: \$QADENA_FOUNDATION_NODES or foundation-nodes)"
            echo "  --expiration   unix time the whole grant lapses.  Only meaningful with --join-only;"
            echo "                 the default (recurring) grant deliberately does not expire, because"
            echo "                 SS rotation recurs for as long as the node runs."
            echo "  --spend-limit  cap the grant TOTAL (default: unset; the periodic budget bounds it)."
            echo "  --join-only    narrow, EXPIRING grant covering only the three sync-enclave"
            echo "                 messages.  The node must be funded another way afterwards, or it"
            echo "                 will stop re-sharing SS keys.  Prefer the default."
            echo "  --period       seconds in a budget period (default 2592000 = 30 days)"
            echo "  --period-limit spend allowed per period (default 1000qdn)"
            echo ""
            echo "By default this is a RECURRING, BOUNDED grant: a PeriodicAllowance of"
            echo "<period-limit> per <period>, refilling indefinitely, restricted to the five"
            echo "messages a node broadcasts over its life (join + SS rotation + re-share)."
            echo "Bounded three ways: per-period budget, message allow-list, and optional total cap."
            echo ""
            echo "  --self-bond <amount>  ALSO send that stake to the node (e.g. 10000qdn), so it can"
            echo "                        self-delegate.  A fee grant cannot supply staked principal;"
            echo "                        only a transfer can.  Once sent the tokens are the operator's"
            echo "                        and slashing burns them -- the foundation keeps no exposure."
            echo "                        Must be at least config.yml's min-self-delegation."
            exit 0 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

[ -n "$node_addr" ] || { echo "--node is required (the address add_full_node.sh printed)"; exit 1; }

case "$node_addr" in
    qadena1*) ;;
    *) echo "--node does not look like a qadena address: $node_addr"; exit 1 ;;
esac

granter_addr=$(qadenad_alias keys show "$granter" -a 2>/dev/null) || granter_addr="$granter"
case "$granter_addr" in
    qadena1*) ;;
    *) echo "could not resolve granter '$granter' to an address -- is it in this keyring?"; exit 1 ;;
esac

[ -n "$expiration" ] || expiration=$(( $(date +%s) + 2592000 ))

# THE MESSAGE ALLOW-LIST.  Full lifecycle by default; the join subset under --join-only.
#
# MsgCreateValidator IS ON IT, and it is the one entry that is not a qadena message.  Bonding is a
# staking message, so a grant that omitted it failed with
#     <granter> does not allow to pay fees for <grantee>
# -- an allowance that exists but does not cover the message, which reads like a missing grant and
# is not.  Observed on pioneer2, 2026-08-31.
#
# THE EXPOSURE IS ONE FEE PER NODE, EVER.  MsgCreateValidator can only succeed once for a given
# operator address; after that the validator exists and every later change is MsgEditValidator or a
# delegation, neither of which is listed here.  So this does not open a recurring cost, which is
# the property the allow-list exists to protect.
#
# It sits in JOIN_MSGS rather than only in LIFE_MSGS because bonding happens during the join, and
# --join-only is the shape used for a node that is funded normally afterwards.
JOIN_MSGS="/qadena.qadena.MsgPioneerAddPublicKey,/qadena.qadena.MsgPioneerUpdateIntervalPublicKeyID,/qadena.qadena.MsgPioneerUpdatePioneerJar,/cosmos.staking.v1beta1.MsgCreateValidator"
LIFE_MSGS="$JOIN_MSGS,/qadena.qadena.MsgPioneerUpdatePublicKey,/qadena.qadena.MsgPioneerUpdateJarRegulator"

if [ "$join_only" = "true" ]; then
    MSGS="$JOIN_MSGS"
    [ -n "$expiration" ] || expiration=$(( $(date +%s) + 2592000 ))
else
    MSGS="$LIFE_MSGS"
fi

echo "-------------------------"
echo "Sponsoring a node"
echo "-------------------------"
echo "  node (grantee): $node_addr"
echo "  granter:        $granter_addr ($granter)"
if [ "$join_only" = "true" ]; then
    echo "  scope:          JOIN ONLY (3 msgs) -- expires $(date -r "$expiration" 2>/dev/null || echo "$expiration")"
    echo ""
    echo "  WARNING: this does NOT cover SS re-share (MsgPioneerUpdatePublicKey).  When this node's"
    echo "           first SS rotation comes due it will fail to pay, and stop re-sharing while"
    echo "           still looking healthy.  Fund it another way before then, or re-run without"
    echo "           --join-only."
else
    echo "  scope:          FULL LIFECYCLE (5 msgs, incl. SS re-share)"
    echo "  budget:         $period_limit per $period s, refilling, no expiry"
fi
[ -n "$spend_limit" ] && echo "  total cap:      $spend_limit"
echo ""

gasflags=(--gas-prices "$minimum_gas_prices" --gas "$gas_auto" --gas-adjustment "$gas_adjustment")

# Build the grant.  Two shapes:
#   join-only   -> AllowedMsgAllowance over a BasicAllowance with an expiration (one-off)
#   default     -> AllowedMsgAllowance over a PeriodicAllowance (recurring, indefinite)
#
# grant_as_foundation (setup_env.sh) is reused ONLY for the join-only shape, because it does not
# take period flags.  It is worth reusing where it fits: it handles the authz-delegated path and it
# revokes first, which matters -- a grantee holds at most ONE allowance per granter, so a new grant
# does not layer over an existing one.
revoke_first() {
    if [ -n "${QADENA_NODE_ADMIN:-}" ]; then
        tmp=$(mktemp)
        qadenad_alias tx feegrant revoke "$granter_addr" "$node_addr" --from "$granter_addr" \
            --generate-only > "$tmp" 2>/dev/null || true
        [ -s "$tmp" ] && qadenad_alias tx authz exec "$tmp" --from "$QADENA_NODE_ADMIN" \
            --fee-granter "$granter_addr" --yes --output json "${gasflags[@]}" >/dev/null 2>&1 || true
        rm -f "$tmp"
    else
        qadenad_alias tx feegrant revoke "$granter_addr" "$node_addr" --from "$granter" \
            --yes --output json "${gasflags[@]}" >/dev/null 2>&1 || true
    fi
    sleep 3
}

if [ "$join_only" = "true" ] && [ -z "$spend_limit" ] && typeset -f grant_as_foundation > /dev/null 2>&1; then
    grant_as_foundation "$granter_addr" "$node_addr" "$MSGS" "${QADENA_NODE_ADMIN:-}" \
        && echo "  ok: join-only fee grant issued"
else
    revoke_first
    grantflags=(--allowed-messages "$MSGS")
    if [ "$join_only" = "true" ]; then
        grantflags+=(--expiration "$expiration")
    else
        grantflags+=(--period "$period" --period-limit "$period_limit")
    fi
    [ -n "$spend_limit" ] && grantflags+=(--spend-limit "$spend_limit")

    if [ -n "${QADENA_NODE_ADMIN:-}" ]; then
        # authz path: the INNER message must be built --from the granter, or authz resolves the
        # grant on the wrong signer and rejects with ErrNoAuthorizationFound.
        tmp=$(mktemp)
        qadenad_alias tx feegrant grant "$granter_addr" "$node_addr" "${grantflags[@]}" \
            --from "$granter_addr" --generate-only > "$tmp" 2>/dev/null \
            || { rm -f "$tmp"; echo "  FAILED to build the grant"; exit 1; }
        out=$(qadenad_alias tx authz exec "$tmp" --from "$QADENA_NODE_ADMIN" \
              --fee-granter "$granter_addr" --yes --output json "${gasflags[@]}" 2>&1); rm -f "$tmp"
    else
        out=$(qadenad_alias tx feegrant grant "$granter_addr" "$node_addr" "${grantflags[@]}" \
              --from "$granter" --yes --output json "${gasflags[@]}" 2>&1)
    fi

    hash=$(echo "$out" | grep '^{' | tail -1 | jq -r '.txhash // ""' 2>/dev/null)
    [ -n "$hash" ] || { echo "  FAILED to broadcast: $(echo "$out" | tail -2)"; exit 1; }
    qadenad_alias query wait-tx "$hash" --timeout 60s >/dev/null 2>&1 || true
    code=$(qadenad_alias query tx "$hash" --output json 2>/dev/null | jq -r '.code // "?"')
    [ "$code" = "0" ] || { echo "  FAILED on chain (code $code): $(qadenad_alias query tx "$hash" --output json 2>/dev/null | jq -r '.raw_log' | head -c 200)"; exit 1; }
    echo "  ok: fee grant issued ($hash)"
fi

# THE STAKE, IF ASKED FOR.  Deliberately AFTER the grant: the send itself costs a fee, and with the
# grant already in place the node could pay for its own later messages even if this step failed
# half-way.  A transfer, not a grant -- x/feegrant separates who signs from who pays fees, and
# staked principal is neither.
if [ -n "$self_bond" ]; then
    echo ""
    echo "Sending the self-bond $self_bond to $node_addr (a transfer; these tokens become the node's own)"
    if [ -n "${QADENA_NODE_ADMIN:-}" ]; then
        tmp=$(mktemp)
        qadenad_alias tx bank send "$granter_addr" "$node_addr" "$self_bond" --from "$granter_addr" \
            --generate-only > "$tmp" 2>/dev/null \
            || { rm -f "$tmp"; echo "  FAILED to build the send"; exit 1; }
        out=$(qadenad_alias tx authz exec "$tmp" --from "$QADENA_NODE_ADMIN" \
              --fee-granter "$granter_addr" --yes --output json "${gasflags[@]}" 2>&1); rm -f "$tmp"
    else
        out=$(qadenad_alias tx bank send "$granter" "$node_addr" "$self_bond" \
              --from "$granter" --yes --output json "${gasflags[@]}" 2>&1)
    fi
    hash=$(echo "$out" | grep '^{' | tail -1 | jq -r '.txhash // ""' 2>/dev/null)
    [ -n "$hash" ] || { echo "  FAILED to broadcast: $(echo "$out" | tail -2)"; exit 1; }
    qadenad_alias query wait-tx "$hash" --timeout 60s >/dev/null 2>&1 || true
    code=$(qadenad_alias query tx "$hash" --output json 2>/dev/null | jq -r '.code // "?"')
    [ "$code" = "0" ] || { echo "  FAILED on chain (code $code): $(qadenad_alias query tx "$hash" --output json 2>/dev/null | jq -r '.raw_log' | head -c 200)"; exit 1; }
    echo "  ok: self-bond sent ($hash)"
fi

echo ""
echo "Verify:"
echo "  qadenad --home \$QADENAHOME query feegrant grants-by-grantee $node_addr"
echo ""
echo "The operator can now answer [y] to add_full_node.sh's prompt."
