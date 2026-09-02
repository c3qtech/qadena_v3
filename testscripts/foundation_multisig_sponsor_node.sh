#!/bin/zsh
#
# Sponsor a joining node from a bucket MULTISIG -- the multisig counterpart of
# testscripts/foundation_sponsor_node.sh, and test fleets only.
#
#   foundation_multisig_sponsor_node.sh --node <pioneer-address> --granter <bucket> \
#       --via <user@node> [--self-bond <amt>aqdn] [--period <s>] [--period-limit <amt>]
#
# SAME JOB, DIFFERENT CUSTODY.  testscripts/foundation_sponsor_node.sh issues the identical recurring
# fee grant, but signs with ONE key on the machine that holds it -- "run this on a box holding the
# foundation key", as its header says.  On a launch chain the sponsoring bucket is an N-of-M
# multisig instead, so the grant has to be signed by M members and no single box can do it.
#
# WHY THIS IS testscripts/ AND ITS COUNTERPART IS NOT.  This signs for the bucket unattended,
# which it can only do because this workstation holds EVERY member key -- precisely the
# arrangement a real bucket exists to prevent.  That is the test fleet's standing shortcut, not
# something to promote into scripts/.  The real operator path is a ceremony among separate
# keyholders: scripts/multisig_sign.sh, driven by hand, as in
# docs/HOWTO-ADD-LAUNCH-CHAIN-NODE.md step 2.
#
# WHAT IT SIGNS.  The grant covers the seven messages a pioneer broadcasts FOR LIFE -- a join-only
# or expiring grant stops SS re-sharing silently, and one without MsgVote makes the fleet
# ungovernable.  With --self-bond it ALSO sends the bond, because no fee grant covers staked
# principal.  Both are signed before either is broadcast, the way the operator docs prescribe so
# members are asked once, which is why the bond's shares carry --sequence-offset 1.
#
set -u
SCRIPT_DIR="${0:A:h}"
source "$SCRIPT_DIR/../scripts/setup_env.sh" > /dev/null 2>&1 || true
QBIN="${qadenabin:-$HOME/qadena/bin}/qadenad"
HOME_DIR="${QADENAHOME:-$HOME/qadena}"

# Same list as testscripts/foundation_sponsor_node.sh and scripts/sponsor_join_node.sh -- keep the
# three together.  A grant that misses one of these fails much later, at an SS re-share or a vote,
# and the node looks healthy until it does.
MSGS="/qadena.qadena.MsgPioneerAddPublicKey,/qadena.qadena.MsgPioneerUpdateIntervalPublicKeyID,/qadena.qadena.MsgPioneerUpdatePioneerJar,/cosmos.staking.v1beta1.MsgCreateValidator,/qadena.qadena.MsgPioneerUpdatePublicKey,/qadena.qadena.MsgPioneerUpdateJarRegulator,/cosmos.gov.v1.MsgVote"

NODE_ADDR="" GRANTER="" VIA="" SELF_BOND="" PERIOD="2592000" PERIOD_LIMIT="1000qdn"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --node)         NODE_ADDR="$2"; shift 2 ;;
        --granter)      GRANTER="$2"; shift 2 ;;
        --via)          VIA="$2"; shift 2 ;;
        --self-bond)    SELF_BOND="$2"; shift 2 ;;
        --period)       PERIOD="$2"; shift 2 ;;
        --period-limit) PERIOD_LIMIT="$2"; shift 2 ;;
        -h|--help)      sed -n '3,27p' "$0"; exit 0 ;;
        *) print -u2 "unknown option: $1"; exit 1 ;;
    esac
done
[[ -n "$NODE_ADDR" && -n "$GRANTER" && -n "$VIA" ]] \
    || { print -u2 "need --node, --granter and --via; see --help"; exit 1 }
[[ "$NODE_ADDR" == qadena1* ]] || { print -u2 "--node must be a bech32 address"; exit 1 }

lk() { "$QBIN" --home "$HOME_DIR" --keyring-backend test "$@" 2>/dev/null }
M="$SCRIPT_DIR/../scripts/multisig_sign.sh"

THR=$(lk keys show "$GRANTER" --output json | jq -r '.pubkey | fromjson? // . | .threshold // empty')
[[ -n "$THR" ]] || { print -u2 "'$GRANTER' is not a multisig key in this keyring"; exit 1 }
CHAIN="${QADENA_CHAIN_ID:-$(ssh -o ConnectTimeout=15 "$VIA" "bash -lc '\$HOME/qadena/bin/qadenad --home \$HOME/qadena status --node tcp://localhost:26657'" 2>/dev/null | tr -d '\r' | jq -r '.node_info.network // empty')}"
[[ -n "$CHAIN" ]] || { print -u2 "cannot determine the chain-id via $VIA"; exit 1 }
export QADENA_CHAIN_ID="$CHAIN"

# ALREADY GRANTED IS DONE.  Re-running after a partial join must not ask the members again.
existing=$(ssh -o ConnectTimeout=15 "$VIA" "bash -lc '\$HOME/qadena/bin/qadenad --home \$HOME/qadena query feegrant grants-by-grantee $NODE_ADDR --output json --node tcp://localhost:26657'" 2>/dev/null \
           | tr -d '\r' | jq -r '.allowances[0].granter // ""')
if [[ -n "$existing" && -z "$SELF_BOND" ]]; then
    print "  $NODE_ADDR already has a grant from $existing -- nothing to do"
    exit 0
fi

print "sponsoring $NODE_ADDR from $GRANTER (${THR}-of-N) on $CHAIN, via $VIA"
wd=$(mktemp -d)
trap 'rm -rf "$wd"' EXIT

need_grant=1
[[ -n "$existing" ]] && { need_grant=0; print "  grant already on chain from $existing -- signing only the bond" }

(( need_grant )) && { "$M" build-feegrant --via-ssh "$VIA" --granter "$GRANTER" --grantee "$NODE_ADDR" \
    --msgs "$MSGS" --period "$PERIOD" --period-limit "$PERIOD_LIMIT" --out "$wd/grant.json" > /dev/null \
    || { print -u2 "  build-feegrant failed"; exit 1 } }
[[ -n "$SELF_BOND" ]] && { "$M" build-send --via-ssh "$VIA" --from "$GRANTER" --to "$NODE_ADDR" \
    --amount "$SELF_BOND" --out "$wd/bond.json" > /dev/null \
    || { print -u2 "  build-send failed"; exit 1 } }

# BOTH SIGNED BEFORE EITHER IS BROADCAST.  The sequence is written when a SHARE is signed, so the
# second transaction's shares must carry +1 -- and only when there IS a first one to follow.
gs=() bs=() boff=0
(( need_grant )) && boff=1
for i in $(seq 1 "$THR"); do
    if (( need_grant )); then
        "$M" sign --via-ssh "$VIA" --tx "$wd/grant.json" --multisig "$GRANTER" \
            --from "${GRANTER}-m${i}" --out "$wd/g${i}.json" > /dev/null \
            || { print -u2 "  ${GRANTER}-m${i} could not sign the grant"; exit 1 }
        gs+=("$wd/g${i}.json")
    fi
    if [[ -n "$SELF_BOND" ]]; then
        "$M" sign --via-ssh "$VIA" --tx "$wd/bond.json" --multisig "$GRANTER" \
            --from "${GRANTER}-m${i}" --out "$wd/b${i}.json" --sequence-offset "$boff" > /dev/null \
            || { print -u2 "  ${GRANTER}-m${i} could not sign the bond"; exit 1 }
        bs+=("$wd/b${i}.json")
    fi
done

if (( need_grant )); then
    "$M" combine --via-ssh "$VIA" --tx "$wd/grant.json" --multisig "$GRANTER" \
        --out "$wd/grant.signed.json" "${gs[@]}" > /dev/null || { print -u2 "  combine (grant) failed"; exit 1 }
    print "  broadcasting the fee grant (${PERIOD_LIMIT} per ${PERIOD}s, recurring, no expiry)"
    "$M" broadcast --via-ssh "$VIA" --tx "$wd/grant.signed.json" || { print -u2 "  the grant did not land"; exit 1 }
fi
if [[ -n "$SELF_BOND" ]]; then
    "$M" combine --via-ssh "$VIA" --tx "$wd/bond.json" --multisig "$GRANTER" \
        --out "$wd/bond.signed.json" "${bs[@]}" > /dev/null || { print -u2 "  combine (bond) failed"; exit 1 }
    print "  broadcasting the self-bond $SELF_BOND"
    "$M" broadcast --via-ssh "$VIA" --tx "$wd/bond.signed.json" \
        || { print -u2 "  the self-bond did not land"; exit 1 }
fi
print "DONE.  $NODE_ADDR sponsored by $GRANTER"
