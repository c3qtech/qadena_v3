#!/bin/zsh
#
# Sign a transaction with a NATIVE MULTISIG, one member at a time.
#
# WHY THIS EXISTS.  nth_node_bringup.sh's funding phase resolves its granter with `keys show` ON
# THE PRIMARY and signs there.  That works when the money is a single key the primary holds.  It
# cannot work when the money is a bucket held as an N-of-M multisig whose members are on
# workstations, hardware wallets, or different continents -- which is every real custody model.
#
# So the funding phase is skipped (`--until 3`, then `--from 5`) and this runs in between, on
# whatever machine holds a member key.  Nothing here needs the chain's keyring, the primary, or
# any key but the one member's.
#
# THE FLOW
#
#   build      once, anywhere -- produces an unsigned tx.  Needs no key.
#   sign       once PER MEMBER, on that member's own machine.  Produces a partial signature.
#   combine    once, anywhere -- N partials -> one signed tx.  Needs no key.
#   broadcast  once, anywhere.
#
# TWO THINGS THAT BIT US, both of which this handles and a hand-rolled ceremony does not:
#
#   THE FEE.  `--generate-only` writes a tx with an EMPTY fee.  The chain's minimum-gas-prices is
#   500000000aqdn, so such a tx is rejected on arrival -- after the whole ceremony.  build always
#   sets --gas and --gas-prices.
#
#   THE SEQUENCE.  Every signature commits to the granter's account sequence, and it is written
#   when a SHARE IS SIGNED -- an unsigned tx has no signer_infos to hold one.  So two transactions
#   signed in one sitting both carry the CURRENT sequence, and the second is invalid the moment
#   the first lands.  Pass --sequence-offset 1 to `sign` for the second, on EVERY share of it:
#   the shares of one tx must agree, or combine produces a signature over nothing.
#
set -u
SCRIPT_DIR="${0:A:h}"
source "$SCRIPT_DIR/setup_env.sh" > /dev/null 2>&1 || true

QBIN="${qadenabin:-$HOME/qadena/bin}/qadenad"
HOME_DIR="${QADENAHOME:-$HOME/qadena}"
BACKEND="${QADENA_KEYRING_BACKEND:-test}"
NODE="${QADENA_NODE:-tcp://localhost:26657}"
CHAIN="${QADENA_CHAIN_ID:-}"
GAS="${QADENA_GAS:-300000}"
GAS_PRICES="${QADENA_GAS_PRICES:-500000000aqdn}"

# --keyring-backend IS NOT A GLOBAL FLAG.  `query` rejects it outright ("unknown flag"), so a
# wrapper that adds it unconditionally breaks every read this script makes -- and breaks them
# QUIETLY, because each call site pipes stderr to /dev/null and reads an empty result as a
# legitimate answer.  Measured 2026-09-01: seq_flags returned nothing (so --sequence-offset was
# silently a no-op) and every broadcast reported failure for a tx that had in fact landed.
q() {
    case "${1:-}" in
        keys|tx) "$QBIN" --home "$HOME_DIR" --keyring-backend "$BACKEND" "$@" ;;
        *)       "$QBIN" --home "$HOME_DIR" "$@" ;;
    esac
}

usage() {
    print "Usage:"
    print "  multisig_sign.sh build-feegrant --granter <msig> --grantee <addr> --msgs <csv>"
    print "                                  [--period <s>] [--period-limit <amt>] --out <file>"
    print "  multisig_sign.sh build-send     --from <msig> --to <addr> --amount <amt> --out <file>"
    print "  multisig_sign.sh sign           --tx <unsigned> --multisig <msig> --from <member> --out <sig>"
    print "  multisig_sign.sh combine        --tx <unsigned> --multisig <msig> --out <signed> <sig>..."
    print "  multisig_sign.sh broadcast      --tx <signed>"
    print ""
    print "  --node       RPC to read account number/sequence from (default \$QADENA_NODE)"
    print "  --chain-id   REQUIRED for sign; a signature is bound to one chain"
    print "  --sequence-offset <n>   SIGN at sequence+n.  Use 1 for every share of the SECOND tx"
    print "                          of a pair, or it is invalid as soon as the first one lands."
    exit 0
}

[[ $# -eq 0 ]] && usage
CMD="$1"; shift
granter="" grantee="" msgs="" period="2592000" period_limit="1000qdn" out=""
from="" to="" amount="" tx="" msig="" seqoff=0
sigs=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --granter) granter="$2"; shift 2 ;;
        --grantee) grantee="$2"; shift 2 ;;
        --msgs) msgs="$2"; shift 2 ;;
        --period) period="$2"; shift 2 ;;
        --period-limit) period_limit="$2"; shift 2 ;;
        --from) from="$2"; shift 2 ;;
        --to) to="$2"; shift 2 ;;
        --amount) amount="$2"; shift 2 ;;
        --out) out="$2"; shift 2 ;;
        --tx) tx="$2"; shift 2 ;;
        --multisig) msig="$2"; shift 2 ;;
        --node) NODE="$2"; shift 2 ;;
        --chain-id) CHAIN="$2"; shift 2 ;;
        --sequence-offset) seqoff="$2"; shift 2 ;;
        --gas) GAS="$2"; shift 2 ;;
        --gas-prices) GAS_PRICES="$2"; shift 2 ;;
        --help|-h) usage ;;
        -*) print -u2 "unknown option: $1"; exit 1 ;;
        *) sigs+=("$1"); shift ;;
    esac
done

[[ -x "$QBIN" ]] || { print -u2 "qadenad not found at $QBIN"; exit 1 }
[[ -n "$CHAIN" ]] || { print -u2 "--chain-id is required: a signature is bound to one chain, and"
                       print -u2 "signing for the wrong one produces a tx that is silently invalid."; exit 1 }

# Resolve a key NAME or an address to an address, so either may be passed anywhere.
addr_of() {
    case "$1" in
        qadena1*) print "$1" ;;
        *) q keys show "$1" -a 2>/dev/null || { print -u2 "no key or address '$1'"; exit 1 } ;;
    esac
}

# THE SEQUENCE, READ ONCE AND PINNED -- USED ONLY BY `sign`.
#
# Not by build: an unsigned tx has no signer_infos to hold a sequence, and passing --offline
# alongside --generate-only and --chain-id is rejected outright ("chain ID cannot be used when
# offline and generate-only flags are set").  The number is written when a share is signed.
seq_flags() {
    local a="$1" acct num sq
    acct=$(q query auth account "$a" --node "$NODE" --output json 2>/dev/null) || return 0
    num=$(print "$acct" | jq -r '..|.account_number? // empty' | head -1)
    sq=$(print "$acct"  | jq -r '..|.sequence? // empty'       | head -1)
    # AN ABSENT sequence MEANS ZERO, NOT UNKNOWN.  A brand-new account -- one that has received
    # coins but never sent a tx -- serialises with no `sequence` field at all.  Returning early on
    # that silently drops --sequence-offset, so the SECOND tx of a pair gets signed at the same
    # sequence as the first and is dead on arrival.  Only a missing account_number is fatal.
    [[ -n "$num" ]] || return 0
    : ${sq:=0}
    print -- "--offline --account-number $num --sequence $(( sq + seqoff ))"
}

case "$CMD" in
build-feegrant)
    [[ -n "$granter" && -n "$grantee" && -n "$msgs" && -n "$out" ]] || usage
    ga=$(addr_of "$granter")
    q tx feegrant grant "$ga" "$grantee" --allowed-messages "$msgs" \
        --period "$period" --period-limit "$period_limit" \
        --from "$ga" --generate-only --chain-id "$CHAIN" --node "$NODE" \
        --gas "$GAS" --gas-prices "$GAS_PRICES" > "$out" || exit 1
    print "built $out  (granter $ga) -- unsigned; the sequence binds at sign"
    ;;
build-send)
    [[ -n "$from" && -n "$to" && -n "$amount" && -n "$out" ]] || usage
    fa=$(addr_of "$from")
    q tx bank send "$fa" "$to" "$amount" \
        --from "$fa" --generate-only --chain-id "$CHAIN" --node "$NODE" \
        --gas "$GAS" --gas-prices "$GAS_PRICES" > "$out" || exit 1
    print "built $out  (from $fa) -- unsigned; the sequence binds at sign"
    ;;
sign)
    [[ -n "$tx" && -n "$msig" && -n "$from" && -n "$out" ]] || usage
    # THE SEQUENCE BINDS HERE, NOT AT BUILD.  An unsigned tx has no signer_infos at all, so
    # --generate-only cannot carry a sequence; it is written when a share is signed.  The number
    # that matters is the MULTISIG's, never the member's -- the member is not the account.
    ma=$(addr_of "$msig")
    q tx sign "$tx" --multisig "$msig" --from "$from" \
        --chain-id "$CHAIN" --node "$NODE" ${=$(seq_flags "$ma")} --output-document "$out" || exit 1
    _sq=$(jq -r '.signatures[0].sequence // "?"' "$out" 2>/dev/null)
    print "  bound to sequence $_sq (offset $seqoff)"
    print "signed by $from -> $out"
    print "  this is ONE share.  Collect enough to meet the threshold, then: combine"
    ;;
combine)
    [[ -n "$tx" && -n "$msig" && -n "$out" && ${#sigs} -gt 0 ]] || usage
    q tx multisign "$tx" "$msig" "${sigs[@]}" \
        --chain-id "$CHAIN" --node "$NODE" > "$out" || exit 1
    n=$(jq -r '.auth_info.signer_infos[0].mode_info.multi.mode_infos | length' "$out" 2>/dev/null)
    print "combined ${#sigs} share(s) -> $out  (tx carries $n signature(s))"
    ;;
broadcast)
    [[ -n "$tx" ]] || usage
    outj=$(q tx broadcast "$tx" --node "$NODE" --output json 2>&1) || { print -u2 "$outj"; exit 1 }
    h=$(print "$outj" | grep '^{' | tail -1 | jq -r '.txhash // ""')
    [[ -n "$h" ]] || { print -u2 "no txhash; broadcast said:"; print -u2 "$outj"; exit 1 }
    print "broadcast $h"
    # POLL, DO NOT ASK ONCE.  `query wait-tx` is best-effort here (it is swallowed by `|| true`
    # so a missing subcommand cannot fail the run), and a single `query tx` straight after can
    # race inclusion: the tx is accepted, not yet in a block, the query returns nothing, and an
    # empty code reads as failure.  Observed 2026-09-01 on a grant that had in fact landed.
    q query wait-tx "$h" --node "$NODE" --timeout 60s > /dev/null 2>&1 || true
    code=""
    for _i in {1..30}; do
        code=$(q query tx "$h" --node "$NODE" --output json 2>/dev/null | jq -r '.code // ""')
        [[ -n "$code" ]] && break
        sleep 2
    done
    if [[ "$code" == "0" ]]; then
        print "  landed, code 0"
    else
        print -u2 "  FAILED on chain, code ${code:-<not included within 60s>}:"
        q query tx "$h" --node "$NODE" --output json 2>/dev/null | jq -r '.raw_log' | head -c 300
        exit 1
    fi
    ;;
*) usage ;;
esac
