#!/bin/zsh
#
# Join ONE sponsored node to a running chain, ceremony included.
#
# WHAT THIS IS FOR.  testscripts/nth_node_bringup.sh does the same steps, but it is a TEST
# harness: it drives both machines over ssh from a workstation, checks peer agreement, and
# carries a pseudo-terminal feeder for the interactive prompts.  This is the operator's
# version -- one node, no test assertions, and it uses add_full_node.sh's --yes/--funded
# flags rather than pretending to be a person typing.
#
# THE SHAPE OF A SPONSORED JOIN.  Three parties, and only one of them is this script's host:
#
#   the JOINER   mints its own pioneer key, signs its own join messages, pays no fees
#   the SPONSOR  a bucket multisig -- signs a recurring FEE GRANT, and the self-bond if the
#                node will validate.  Its keys are NOT on the joiner and NOT on the primary.
#   the PRIMARY  an existing node; used only as an RPC endpoint and a seed
#
# So the ceremony is deliberately NOT automated here.  This script stops, prints exactly what
# has to be signed, and waits for it to appear ON CHAIN before continuing.  A script that
# could sign for the sponsor would have to hold the sponsor's keys, which is the property the
# multisig exists to prevent.
#
#   ./sponsor_join_node.sh --pioneer qfi-pioneer5 --advertise-ip-address 10.0.0.5 \
#       --primary-ip 10.0.0.1 --granter <bucket-address> [--validator]
#
# Run it ON THE JOINER.  Needs the release package installed (scripts/install_release.sh).
#
set -u
SCRIPT_DIR="${0:A:h}"
source "$SCRIPT_DIR/setup_env.sh" > /dev/null 2>&1 || true
QBIN="${qadenabin:-$HOME/qadena/bin}/qadenad"
HOME_DIR="${QADENAHOME:-$HOME/qadena}"

PIONEER="" ADVERTISE="" PRIMARY_IP="" GRANTER="" VALIDATOR=0 SECOND_IP="" TRUST_OFFSET=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --pioneer) PIONEER="$2"; shift 2 ;;
        --advertise-ip-address) ADVERTISE="$2"; shift 2 ;;
        --primary-ip) PRIMARY_IP="$2"; shift 2 ;;
        --second-ip) SECOND_IP="$2"; shift 2 ;;
        --granter) GRANTER="$2"; shift 2 ;;
        --validator) VALIDATOR=1; shift ;;
        --trust-height-offset) TRUST_OFFSET="$2"; shift 2 ;;
        --help|-h)
            print "Usage: sponsor_join_node.sh --pioneer <name> --advertise-ip-address <ip>"
            print "                            --primary-ip <ip> --granter <bucket-address>"
            print "                            [--validator] [--second-ip <ip>] [--trust-height-offset <n>]"
            print ""
            print "  --pioneer   MUST be unused on the chain.  Names outlive the machine: wiping a"
            print "              node frees nothing, the chain keeps the registration forever."
            print "  --granter   the sponsoring bucket's ADDRESS (not a key name -- its keys are"
            print "              somewhere else entirely, which is the point)."
            print "  --validator also wait for the self-bond and convert at the end.  Without it"
            print "              this produces a FULL NODE, which needs no stake, ever."
            exit 0 ;;
        *) print -u2 "unknown option: $1"; exit 1 ;;
    esac
done
[[ -n "$PIONEER" && -n "$ADVERTISE" && -n "$PRIMARY_IP" && -n "$GRANTER" ]] \
    || { print -u2 "missing required option; see --help"; exit 1 }
[[ -x "$QBIN" ]] || { print -u2 "no qadenad at $QBIN -- install the release package first"; exit 1 }

NODE="tcp://${PRIMARY_IP}:26657"
q() { "$QBIN" --home "$HOME_DIR" "$@"; }
qk() { "$QBIN" --home "$HOME_DIR" --keyring-backend test "$@"; }

CHAIN=$(curl -s --max-time 8 "http://${PRIMARY_IP}:26657/status" | jq -r '.result.node_info.network // empty')
[[ -n "$CHAIN" ]] || { print -u2 "cannot reach the primary at ${PRIMARY_IP}:26657"; exit 1 }
print "chain: $CHAIN   primary: $PRIMARY_IP   sponsor: $GRANTER"

# THE NAME CHECK IS FIRST, because everything after it is expensive and none of it can be
# undone.  add_full_node.sh refuses a registered name -- but only after wiping this node.
if q q qadena list-interval-public-key-id --node "$NODE" --output json 2>/dev/null \
   | jq -e --arg n "$PIONEER" '[.intervalPublicKeyID[]?.nodeID] | index($n)' > /dev/null; then
    print -u2 "'$PIONEER' is ALREADY REGISTERED on $CHAIN.  Pick an unused name -- the chain"
    print -u2 "keeps registrations forever, even after the node that made them is destroyed."
    exit 1
fi

# ---------------------------------------------------------------- 1. mint, then stop
print ""
print "=== 1/4  minting $PIONEER (this wipes any prior node state on THIS machine) ==="
extra=()
[[ -n "$SECOND_IP" ]]     && extra+=(--genesis-pioneer-second-ip-address "$SECOND_IP")
[[ -n "$TRUST_OFFSET" ]]  && extra+=(--trust-height-offset "$TRUST_OFFSET")
"$SCRIPT_DIR/add_full_node.sh" --pioneer "$PIONEER" \
    --advertise-ip-address "$ADVERTISE" \
    --genesis-pioneer-first-ip-address "$PRIMARY_IP" \
    --foundation-sponsored "$GRANTER" \
    "${extra[@]}" --yes --on-existing s --stop-for-funding || exit 1

ADDR=$(qk keys show "$PIONEER" -a 2>/dev/null | tr -d '\r')
[[ "$ADDR" == qadena1* ]] || { print -u2 "could not read $PIONEER's address after minting"; exit 1 }

# ---------------------------------------------------------------- 2. the ceremony (not ours)
MSGS="/qadena.qadena.MsgPioneerAddPublicKey,/qadena.qadena.MsgPioneerUpdateIntervalPublicKeyID,/qadena.qadena.MsgPioneerUpdatePioneerJar,/cosmos.staking.v1beta1.MsgCreateValidator,/qadena.qadena.MsgPioneerUpdatePublicKey,/qadena.qadena.MsgPioneerUpdateJarRegulator,/cosmos.gov.v1.MsgVote"
FLOOR=$(dasel -f "$HOME_DIR/config/config.yml" 'validators.first().app.min-self-delegation' 2>/dev/null | tr -d '\r"')

print ""
print "=== 2/4  WAITING FOR THE SPONSOR ==================================================="
print "  joiner:   $ADDR"
print "  chain-id: $CHAIN"
print ""
print "  On the machine holding $GRANTER's keys, run scripts/multisig_sign.sh:"
print "    export QADENA_NODE=$NODE QADENA_CHAIN_ID=$CHAIN"
print "    multisig_sign.sh build-feegrant --granter <msig> --grantee $ADDR \\"
print "        --msgs '$MSGS' --out grant.json"
if (( VALIDATOR )); then
print "    multisig_sign.sh build-send --from <msig> --to $ADDR --amount ${FLOOR}aqdn --out bond.json"
fi
print "    # each member, on their own machine:"
print "    multisig_sign.sh sign --tx grant.json --multisig <msig> --from <member> --out gN.json"
if (( VALIDATOR )); then
print "    multisig_sign.sh sign --tx bond.json  --multisig <msig> --from <member> --out bN.json --sequence-offset 1"
print "    #   ^ the offset goes on SIGN, on every share of the SECOND tx, and only while the"
print "    #     first has NOT yet landed.  The sequence is written when a share is signed."
fi
print "    multisig_sign.sh combine --tx grant.json --multisig <msig> --out sg.json g1.json g2.json g3.json"
print "    multisig_sign.sh broadcast --tx sg.json"
if (( VALIDATOR )); then
print "    multisig_sign.sh combine --tx bond.json --multisig <msig> --out sb.json b1.json b2.json b3.json"
print "    multisig_sign.sh broadcast --tx sb.json"
fi
print ""
print "  The grant must be RECURRING and must NOT expire: SS re-sharing runs for the life of"
print "  the node, and a lapsed grant stops it silently while the node still looks healthy."
print "==================================================================================="
print ""

print -n "  waiting for the fee grant"
for i in {1..240}; do
    g=$(q q feegrant grants-by-grantee "$ADDR" --node "$NODE" --output json 2>/dev/null | jq -r '.allowances | length' 2>/dev/null)
    [[ "${g:-0}" -gt 0 ]] && { print " -- arrived"; break }
    print -n "."; sleep 15
    (( i == 240 )) && { print ""; print -u2 "  gave up after an hour"; exit 1 }
done
if (( VALIDATOR )); then
    print -n "  waiting for the self-bond"
    for i in {1..240}; do
        b=$(q q bank balances "$ADDR" --node "$NODE" --output json 2>/dev/null \
            | jq -r '[.balances[]?|select(.denom=="aqdn").amount]|first // "0"')
        [[ "$b" != "0" ]] && (( $(print "$b >= $FLOOR" | bc 2>/dev/null || print 0) )) \
            && { print " -- arrived ($b aqdn)"; break }
        print -n "."; sleep 15
        (( i == 240 )) && { print ""; print -u2 "  gave up after an hour"; exit 1 }
    done
fi

# ---------------------------------------------------------------- 3. finish the join
print ""
print "=== 3/4  joining ==="
# --on-existing c KEEPS the key just funded.  's' here would erase it and strand the coins:
# a funded pioneer address cannot send them back (AML 1159).
"$SCRIPT_DIR/add_full_node.sh" --pioneer "$PIONEER" \
    --advertise-ip-address "$ADVERTISE" \
    --genesis-pioneer-first-ip-address "$PRIMARY_IP" \
    --foundation-sponsored "$GRANTER" \
    "${extra[@]}" --yes --on-existing c --funded --no-start-node || exit 1

print "  starting the node"
"$SCRIPT_DIR/start_qadena.sh" > /dev/null 2>&1
for i in {1..120}; do
    curl -s --max-time 4 localhost:26657/status >/dev/null 2>&1 && break
    sleep 5
done
print -n "  catching up"
for i in {1..360}; do
    cu=$(curl -s --max-time 4 localhost:26657/status 2>/dev/null | jq -r '.result.sync_info.catching_up // true')
    [[ "$cu" == "false" ]] && { print " -- caught up"; break }
    print -n "."; sleep 10
done

# ---------------------------------------------------------------- 4. convert, if asked
if (( VALIDATOR )); then
    print ""
    print "=== 4/4  converting to validator ==="
    # The stake is min-self-delegation in QDN; convert_to_validator.sh bonds exactly that when
    # sponsored, and pays its own fee from the grant.
    stake_qdn=$(( FLOOR / 1000000000000000000 ))
    "$SCRIPT_DIR/convert_to_validator.sh" --validator-stake "$stake_qdn" \
        --foundation-sponsored "$GRANTER" || exit 1
else
    print ""
    print "=== 4/4  full node, not converting ==="
    print "  This node needs no stake.  To validate later, once a self-bond has been sent:"
    print "    scripts/convert_to_validator.sh --validator-stake <qdn> --foundation-sponsored $GRANTER"
fi

print ""
print "DONE.  $PIONEER = $ADDR"
print "  height:  $(curl -s --max-time 4 localhost:26657/status 2>/dev/null | jq -r .result.sync_info.latest_block_height)"
print "  verify:  blocks advancing against the WALL CLOCK (catching_up lies on a halted node),"
print "           and '$PIONEER' present in: qadenad q qadena list-interval-public-key-id"
