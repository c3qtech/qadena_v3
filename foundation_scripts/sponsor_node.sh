#!/bin/zsh
#
# FOUNDATION -> a joining node: issue the lifetime fee grant from a bucket MULTISIG, and optionally
# the self-bond.  Parameters only -- no ambient environment, no --via.
#
#   foundation_scripts/sponsor_node.sh --grantee qadena1<pioneer> \
#       --coord-home ~/qfi-testnet-fleet-launch/coord \
#       --keyring-passfile ~/qfi-testnet-fleet-launch/keyring-password \
#       --node tcp://45.115.225.104:26657 \
#       [--granter nodeops] [--members nodeops-m1,nodeops-m2] [--self-bond 10000qdn]
#
# WHY THIS EXISTS ALONGSIDE testscripts/foundation_multisig_sponsor_node.sh.  That one is the test
# fleet's shortcut: it reads its keyring from $QADENAHOME, defaults the backend to `test`, derives
# the signer list as <granter>-m1..mTHR, and reaches the chain over ssh with --via because the
# workstation could not dial the RPC.  Every one of those is an assumption about one setup.
#
# This follows the COORD CONVENTION the rest of foundation_scripts/ uses -- the bucket multisigs
# live in a coordinator home with a `file` backend, named on the command line -- and talks to the
# chain directly, because a foundation box that can run the ceremony can reach the node.
#
# STILL NOT A SEPARATE-KEYHOLDER CEREMONY.  It signs with every member key it is given, so it
# requires them all in one keyring.  That is exactly what the other foundation_scripts ceremonies
# do (before_step_1 signs the fund and stake transactions the same way), and it is appropriate
# wherever the foundation genuinely holds the coordinator keyring.  Where the members are separate
# people, use --print-ceremony and hand each of them their line.
#
# --node IS THE RPC, NOT THE NODE BEING SPONSORED.  The testscripts version spells the pioneer
# address --node, and foundation_scripts spells the RPC --node; one of the two had to give, and the
# RPC meaning is the one every other script here already uses.  The address is --grantee.  A bech32
# passed to --node is caught below rather than producing an unroutable endpoint.

set -u

SCRIPT_DIR="${0:A:h}"
MSIG="$SCRIPT_DIR/../scripts/multisig_sign.sh"
[[ -x "$MSIG" ]] || { print -u2 "cannot run $MSIG"; exit 1 }

GRANTEE="" GRANTER="nodeops" MEMBERS="" SELF_BOND=""
PERIOD="2592000" PERIOD_LIMIT="1000qdn"
COORD_HOME="" BACKEND="file" KEYRING_PASSFILE="" NODE="" WORKDIR="" PRINT_ONLY=0

usage() {
    print -r -- "Usage: sponsor_node.sh --grantee <qadena1...> --coord-home <dir> [options]"
    print -r -- ""
    print -r -- "  --grantee <addr>     the JOINING NODE's pioneer address, printed by"
    print -r -- "                       add_full_node.sh at its funding gate.  NOT --node."
    print -r -- "  --granter <bucket>   multisig that pays.  Default $GRANTER"
    print -r -- "  --members <csv>      member keys that sign.  Default <granter>-m1..m<threshold>,"
    print -r -- "                       the naming derive_launch_keys.sh uses"
    print -r -- "  --self-bond <amt>    ALSO send this as a transfer.  A validator needs it: staked"
    print -r -- "                       principal becomes the node's own and slashing burns it, so"
    print -r -- "                       no fee grant can carry it.  Omit for a full node."
    print -r -- "  --coord-home <dir>   coordinator keyring holding the bucket and its members"
    print -r -- "  --keyring-backend    default $BACKEND"
    print -r -- "  --keyring-passfile <file>   first line is the passphrase"
    print -r -- "  --node <rpc>         the CHAIN's RPC.  Default \$QADENA_NODE"
    print -r -- "  --period <s> / --period-limit <amt>   allowance refill.  Default $PERIOD s / $PERIOD_LIMIT"
    print -r -- "  --workdir <dir>      keep the ceremony's files here (default: a temp dir, kept on failure)"
    print -r -- "  --print-ceremony     print the per-member commands and send nothing"
    print -r -- ""
    print -r -- "  The grant covers the EIGHT messages a pioneer broadcasts for life and does NOT"
    print -r -- "  expire.  A join-only or expiring grant stops SS re-sharing silently, months later."
}

while (( $# )); do
    case "$1" in
        --grantee)          GRANTEE="$2"; shift 2 ;;
        --granter)          GRANTER="$2"; shift 2 ;;
        --members)          MEMBERS="$2"; shift 2 ;;
        --self-bond)        SELF_BOND="$2"; shift 2 ;;
        --period)           PERIOD="$2"; shift 2 ;;
        --period-limit)     PERIOD_LIMIT="$2"; shift 2 ;;
        --coord-home)       COORD_HOME="$2"; shift 2 ;;
        --keyring-backend)  BACKEND="$2"; shift 2 ;;
        --keyring-passfile) KEYRING_PASSFILE="$2"; shift 2 ;;
        --node)             NODE="$2"; shift 2 ;;
        --workdir)          WORKDIR="$2"; shift 2 ;;
        --print-ceremony)   PRINT_ONLY=1; shift ;;
        --help|-h)          usage; exit 0 ;;
        *) print -u2 -- "unknown option: $1"; usage >&2; exit 1 ;;
    esac
done

NODE="${NODE:-${QADENA_NODE:-}}"

# THE --node / --grantee COLLISION, CAUGHT RATHER THAN DOCUMENTED.  Anyone arriving from the
# testscripts version will type the address into --node out of habit; without this it becomes an
# RPC endpoint that cannot be dialled, and the failure names the network rather than the mistake.
case "$NODE" in
    qadena1*) print -u2 -- "--node is the chain's RPC; you passed an address.  Use --grantee $NODE"; exit 1 ;;
esac
case "$GRANTEE" in
    qadena1*) ;;
    "")  print -u2 -- "--grantee is required (the joining node's pioneer address)"; usage >&2; exit 1 ;;
    *)   print -u2 -- "--grantee must be a qadena1 address, got '$GRANTEE'"; exit 1 ;;
esac
[[ -n "$COORD_HOME" ]] || { print -u2 -- "--coord-home is required"; usage >&2; exit 1 }
[[ -d "$COORD_HOME" ]] || { print -u2 -- "no such directory: $COORD_HOME"; exit 1 }
[[ -n "$NODE" ]] || { print -u2 -- "--node is required (or export QADENA_NODE)"; exit 1 }

KRPASS=""
if [[ -n "$KEYRING_PASSFILE" ]]; then
    [[ -r "$KEYRING_PASSFILE" ]] || { print -u2 -- "cannot read $KEYRING_PASSFILE"; exit 1 }
    KRPASS=$(head -1 "$KEYRING_PASSFILE")
    [[ -n "$KRPASS" ]] || { print -u2 -- "$KEYRING_PASSFILE is empty"; exit 1 }
elif [[ "$BACKEND" == "file" ]]; then
    [[ -t 0 ]] || { print -u2 -- "backend is 'file' and there is no terminal; pass --keyring-passfile"; exit 1 }
    printf "Coordinator keyring passphrase (%s, hidden): " "$COORD_HOME" >&2
    IFS= read -rs KRPASS; print "" >&2
    [[ -n "$KRPASS" ]] || { print -u2 -- "empty passphrase"; exit 1 }
fi

QBIN="${qadenabin:-$HOME/qadena/bin}/qadenad"
[[ -x "$QBIN" ]] || { print -u2 -- "no qadenad at $QBIN"; exit 1 }

# READ-ONLY, AGAINST THE COORDINATOR KEYRING.  Feeds the passphrase the same way the other
# foundation scripts do; qadenad asks once per invocation and extra lines are harmless.
qk() {
    if [[ -n "$KRPASS" ]]; then
        { repeat 16 print -r -- "$KRPASS" } 2>/dev/null \
            | "$QBIN" --home "$COORD_HOME" --keyring-backend "$BACKEND" "$@" 2>/dev/null
    else
        "$QBIN" --home "$COORD_HOME" --keyring-backend "$BACKEND" "$@" 2>/dev/null
    fi
}

# THE CHAIN-ID IS SIGNED, AND THE COORDINATOR HOME DOES NOT KNOW IT.  Its client.toml holds
# whatever derive_launch_keys.sh rendered -- on qfi-testnet, the DEVNET id against a testnet chain.
# Signing with that produces a signature the chain cannot verify, which cosmos/evm reports as a
# recovered amino panic naming neither the chain-id nor the signature.  Ask the node.
CHAIN="${QADENA_CHAIN_ID:-$("$QBIN" status --node "$NODE" 2>/dev/null | jq -r '.node_info.network // empty')}"
[[ -n "$CHAIN" ]] || { print -u2 -- "cannot reach $NODE to read the chain-id; set QADENA_CHAIN_ID"; exit 1 }

THR=$(qk keys show "$GRANTER" --output json | jq -r '.pubkey | fromjson? // . | .threshold // empty')
[[ -n "$THR" ]] || {
    print -u2 -- "'$GRANTER' is not a multisig key in $COORD_HOME (backend $BACKEND)."
    print -u2 -- "  The launch buckets live in the COORDINATOR keyring -- check --coord-home."
    exit 1 }

# DEFAULT THE SIGNERS TO THE BUCKET'S OWN NAMING.  derive_launch_keys.sh mints members as
# <bucket>-m1..mN, so the threshold alone determines who signs.  --members overrides for a bucket
# whose members are named otherwise, or to choose WHICH threshold-many sign.
if [[ -z "$MEMBERS" ]]; then
    _m=(); for i in $(seq 1 "$THR"); do _m+=("${GRANTER}-m${i}"); done
    MEMBERS="${(j:,:)_m}"
fi
typeset -a MEM; MEM=(${(s:,:)MEMBERS})
(( ${#MEM} >= THR )) || {
    print -u2 -- "$GRANTER needs $THR signatures; --members names only ${#MEM}"; exit 1 }

# SAME EIGHT MESSAGES AS testscripts/foundation_sponsor_node.sh AND scripts/sponsor_join_node.sh.
# Keep the three in step: a grant missing one of these fails much later -- at an SS re-share or a
# governance vote -- and the node looks healthy until it does.
JOIN_MSGS="/qadena.qadena.MsgPioneerAddPublicKey,/qadena.qadena.MsgPioneerUpdateIntervalPublicKeyID,/qadena.qadena.MsgPioneerUpdatePioneerJar,/cosmos.staking.v1beta1.MsgCreateValidator"
# MsgUnjail IS A LIFETIME MESSAGE TOO -- IT IS HOW A JAILED SPONSORED VALIDATOR COMES BACK.  A
# toll-free validator holds zero liquid QDN (its self-bond is fully staked), so without this it
# cannot pay for its own unjail and stays jailed forever.
LIFE_MSGS="$JOIN_MSGS,/qadena.qadena.MsgPioneerUpdatePublicKey,/qadena.qadena.MsgPioneerUpdateJarRegulator,/cosmos.gov.v1.MsgVote,/cosmos.slashing.v1beta1.MsgUnjail"

if [[ -z "$WORKDIR" ]]; then
    WORKDIR=$(mktemp -d "${TMPDIR:-/tmp}/sponsor-node.XXXXXX") || exit 1
fi
mkdir -p "$WORKDIR"; chmod 700 "$WORKDIR"

print -r -- "==================================================================="
print -r -- "FOUNDATION -> node sponsorship"
print -r -- "==================================================================="
print -r -- "  grantee   $GRANTEE"
print -r -- "  granter   $GRANTER  ($THR-of-N; signing as ${(j:, :)MEM[1,THR]})"
print -r -- "  grant     $PERIOD_LIMIT per ${PERIOD}s, recurring, NO EXPIRY, 7 messages"
[[ -n "$SELF_BOND" ]] && print -r -- "  self-bond $SELF_BOND  (a transfer -- no grant covers staked principal)"
print -r -- "  chain     $CHAIN via $NODE"
print -r -- "  files     $WORKDIR"
print -r -- ""

msig() {
    QADENA_KEYRING_PASS="$KRPASS" QADENA_CHAIN_ID="$CHAIN" QADENA_SIGNERS="$THR" \
    QADENAHOME="$COORD_HOME" QADENA_KEYRING_BACKEND="$BACKEND" \
        "$MSIG" "$@" --node "$NODE"
}

# BUILD BOTH BEFORE SIGNING EITHER, and sign both before broadcasting either -- the operator docs'
# rule, so members are asked once.  The sequence is stamped when a SHARE is signed, not at build,
# so the bond's shares must carry +1 -- and only when there is a grant ahead of them.
msig build-feegrant --granter "$GRANTER" --grantee "$GRANTEE" --msgs "$LIFE_MSGS" \
        --period "$PERIOD" --period-limit "$PERIOD_LIMIT" --out "$WORKDIR/grant.json" > /dev/null \
    || { print -u2 -- "build-feegrant failed (files kept in $WORKDIR)"; exit 1 }
if [[ -n "$SELF_BOND" ]]; then
    msig build-send --from "$GRANTER" --to "$GRANTEE" --amount "$SELF_BOND" \
            --out "$WORKDIR/bond.json" > /dev/null \
        || { print -u2 -- "build-send failed (files kept in $WORKDIR)"; exit 1 }
fi

if (( PRINT_ONLY )); then
    print -r -- "# Run these where the members are, then broadcast:"
    i=1
    for m in ${MEM[1,THR]}; do
        print -r -- "  scripts/multisig_sign.sh sign --tx $WORKDIR/grant.json --multisig $GRANTER \\"
        print -r -- "        --from $m --chain-id $CHAIN --out $WORKDIR/g$i.json"
        [[ -n "$SELF_BOND" ]] && {
        print -r -- "  scripts/multisig_sign.sh sign --tx $WORKDIR/bond.json --multisig $GRANTER \\"
        print -r -- "        --from $m --chain-id $CHAIN --sequence-offset 1 --out $WORKDIR/b$i.json" }
        i=$(( i + 1 ))
    done
    print -r -- "  scripts/multisig_sign.sh combine --tx $WORKDIR/grant.json --multisig $GRANTER \\"
    print -r -- "        --out $WORKDIR/grant.signed.json $WORKDIR/g*.json"
    print -r -- "  scripts/multisig_sign.sh broadcast --tx $WORKDIR/grant.signed.json"
    [[ -n "$SELF_BOND" ]] && {
    print -r -- "  scripts/multisig_sign.sh combine --tx $WORKDIR/bond.json --multisig $GRANTER \\"
    print -r -- "        --out $WORKDIR/bond.signed.json $WORKDIR/b*.json"
    print -r -- "  scripts/multisig_sign.sh broadcast --tx $WORKDIR/bond.signed.json" }
    exit 0
fi

typeset -a GS BS; GS=(); BS=()
i=1
for m in ${MEM[1,THR]}; do
    print -r -- "  signing the grant as $m"
    msig sign --tx "$WORKDIR/grant.json" --multisig "$GRANTER" --from "$m" \
            --out "$WORKDIR/g$i.json" > /dev/null \
        || { print -u2 -- "  $m could not sign the grant (files kept in $WORKDIR)"; exit 1 }
    GS+=("$WORKDIR/g$i.json")
    if [[ -n "$SELF_BOND" ]]; then
        print -r -- "  signing the bond  as $m  (sequence +1)"
        msig sign --tx "$WORKDIR/bond.json" --multisig "$GRANTER" --from "$m" \
                --sequence-offset 1 --out "$WORKDIR/b$i.json" > /dev/null \
            || { print -u2 -- "  $m could not sign the bond (files kept in $WORKDIR)"; exit 1 }
        BS+=("$WORKDIR/b$i.json")
    fi
    i=$(( i + 1 ))
done

print -r -- ""
msig combine --tx "$WORKDIR/grant.json" --multisig "$GRANTER" \
        --out "$WORKDIR/grant.signed.json" "${GS[@]}" > /dev/null \
    || { print -u2 -- "combine (grant) failed -- too few shares for the threshold?"; exit 1 }
print -r -- "  broadcasting the fee grant"
msig broadcast --tx "$WORKDIR/grant.signed.json" \
    || { print -u2 -- "the grant did not land (files kept in $WORKDIR)"; exit 1 }

if [[ -n "$SELF_BOND" ]]; then
    msig combine --tx "$WORKDIR/bond.json" --multisig "$GRANTER" \
            --out "$WORKDIR/bond.signed.json" "${BS[@]}" > /dev/null \
        || { print -u2 -- "combine (bond) failed"; exit 1 }
    print -r -- "  broadcasting the self-bond $SELF_BOND"
    msig broadcast --tx "$WORKDIR/bond.signed.json" \
        || { print -u2 -- "the bond did not land (files kept in $WORKDIR)"; exit 1 }
fi

print -r -- ""
print -r -- "==================================================================="
print -r -- "DONE.  Confirm what the node now holds:"
print -r -- ""
print -r -- "    qadenad query feegrant grants-by-grantee $GRANTEE --node $NODE"
[[ -n "$SELF_BOND" ]] && \
print -r -- "    qadenad query bank balances $GRANTEE --node $NODE"
print -r -- ""
print -r -- "  The joining node can now re-run add_full_node.sh without --stop-for-funding."
print -r -- "==================================================================="
rm -rf "$WORKDIR"
