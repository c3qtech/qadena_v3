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
VIA_SSH="${QADENA_VIA_SSH:-}"

# --keyring-backend IS NOT A GLOBAL FLAG.  `query` rejects it outright ("unknown flag"), so a
# wrapper that adds it unconditionally breaks every read this script makes -- and breaks them
# QUIETLY, because each call site pipes stderr to /dev/null and reads an empty result as a
# legitimate answer.  Measured 2026-09-01: seq_flags returned nothing (so --sequence-offset was
# silently a no-op) and every broadcast reported failure for a tx that had in fact landed.
# THE PASSPHRASE IS FED PER CALL, NOT PER SCRIPT.  With backend=file every `keys` and every `tx`
# prompts, and ONE INVOCATION OF THIS SCRIPT MAKES SEVERAL -- `sign` alone resolves the multisig
# address, reads the account sequence, then signs.  A caller that pipes the passphrase into the
# script as a whole therefore fails: the first qadenad drains the pipe and every later one gets
# EOF, which the backend counts as a wrong attempt.  Three of those and the keyring locks with
# "too many failed passphrase attempts" -- a message that blames the passphrase when the passphrase
# was right.  Measured 2026-09-05.
#
# So the caller exports QADENA_KEYRING_PASS and each invocation gets its own copy.  Twice, because
# the backend asks for confirmation the first time it opens a keyring and ignores the surplus line
# afterwards.  It is an environment variable rather than an argument so it stays out of `ps`; it is
# still readable by this user's own processes, which is the same trust boundary as the keyring file.
q() {
    local -a cmd
    case "${1:-}" in
        keys|tx) cmd=("$QBIN" --home "$HOME_DIR" --keyring-backend "$BACKEND" "$@") ;;
        *)       cmd=("$QBIN" --home "$HOME_DIR" "$@") ;;
    esac
    if [[ -n "${QADENA_KEYRING_PASS:-}" && ( "${1:-}" == keys || "${1:-}" == tx ) ]]; then
        { print -r -- "$QADENA_KEYRING_PASS"; print -r -- "$QADENA_KEYRING_PASS" } | "${cmd[@]}"
    else
        "${cmd[@]}"
    fi
}

# THE CHAIN-TOUCHING CALLS, AND ONLY THOSE.  With --via-ssh they run qadenad ON THE NODE instead
# of here, which matters when this workstation cannot reach the RPC at all -- a restrictive
# corporate network, a filtered VPN, or (observed 2026-09-02) an outbound policy that permits
# dynamically-linked binaries while denying Go ones, so `curl` reaches the node and `qadenad`
# does not.  Without this the script simply cannot run from such a machine.
#
# SIGNING NEVER COMES THROUGH HERE.  Only two things cross the wire: the account number and
# sequence, and the FULLY SIGNED transaction -- which is public by definition, since the next
# thing that happens to it is broadcast to every validator.  No key, no share, no mnemonic ever
# leaves this machine, which is the property the multisig exists to create.
qnode() {
    if [[ -n "$VIA_SSH" ]]; then
        ssh -o ConnectTimeout=10 "$VIA_SSH" "bash -lc $(printf '%q' \
            "\$HOME/qadena/bin/qadenad --home \$HOME/qadena $* --node tcp://localhost:26657")"
    else
        q "$@" --node "$NODE"
    fi
}

usage() {
    print "Usage:"
    print "  multisig_sign.sh build-feegrant --granter <msig> --grantee <addr> --msgs <csv>"
    print "                                  [--period <s>] [--period-limit <amt>] --out <file>"
    print "  multisig_sign.sh build-send     --from <msig> --to <addr> --amount <amt> --out <file>"
    print "  multisig_sign.sh build-delegate --from <msig> --validator <valoper> --amount <amt> --out <f>"
    print "  multisig_sign.sh build-deposit  --from <msig> --proposal <id> --amount <amt> --out <f>"
    print "  multisig_sign.sh build-vote     --from <msig> --proposal <id> --vote <opt> --out <f>"
    print "  multisig_sign.sh sign           --tx <unsigned> --multisig <msig> --from <member> --out <sig>"
    print "  multisig_sign.sh combine        --tx <unsigned> --multisig <msig> --out <signed> <sig>..."
    print "  multisig_sign.sh broadcast      --tx <signed>"
    print ""
    print "  --node       RPC to read account number/sequence from (default \$QADENA_NODE)"
    print "  --via-ssh <user@host>   run the CHAIN-touching calls on that node over ssh, for a"
    print "               machine that cannot reach the RPC itself.  Signing stays local: only the"
    print "               account number/sequence and the already-public signed tx cross the wire."
    print "  --chain-id   REQUIRED for sign; a signature is bound to one chain"
    print "  --sequence-offset <n>   SIGN at sequence+n.  Use 1 for every share of the SECOND tx"
    print "                          of a pair, or it is invalid as soon as the first one lands."
    # EXIT NON-ZERO BY DEFAULT.  This used to `exit 0`, so every misuse looked like SUCCESS to a
    # caller: a mistyped subcommand printed usage, returned 0, and the script that invoked it
    # carried on believing the transaction had been built.  Observed 2026-09-02 -- a whole
    # ceremony "succeeded" without signing or broadcasting anything, and the only symptom was a
    # four-minute wait for coins that were never sent.  --help passes 0 explicitly.
    exit ${1:-1}
}

[[ $# -eq 0 ]] && usage
CMD="$1"; shift
# HELP IS HANDLED HERE, not in the option loop below: $1 is taken as the SUBCOMMAND, so
# `multisig_sign.sh --help` never reaches that loop and would otherwise die on the --chain-id
# check with a message about signatures.
[[ "$CMD" == "--help" || "$CMD" == "-h" ]] && usage 0
granter="" grantee="" msgs="" period="2592000" period_limit="1000qdn" out=""
from="" to="" amount="" tx="" msig="" seqoff=0
validator="" proposal="" vote_opt=""
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
        --validator) validator="$2"; shift 2 ;;
        --proposal) proposal="$2"; shift 2 ;;
        --vote) vote_opt="$2"; shift 2 ;;
        --out) out="$2"; shift 2 ;;
        --tx) tx="$2"; shift 2 ;;
        --multisig) msig="$2"; shift 2 ;;
        --node) NODE="$2"; shift 2 ;;
        --via-ssh) VIA_SSH="$2"; shift 2 ;;
        --chain-id) CHAIN="$2"; shift 2 ;;
        --sequence-offset) seqoff="$2"; shift 2 ;;
        --gas) GAS="$2"; shift 2 ;;
        --gas-prices) GAS_PRICES="$2"; shift 2 ;;
        --help|-h) usage 0 ;;
        -*) print -u2 "unknown option: $1"; exit 1 ;;
        *) sigs+=("$1"); shift ;;
    esac
done

[[ -x "$QBIN" ]] || { print -u2 "qadenad not found at $QBIN"; exit 1 }
[[ -n "$CHAIN" ]] || { print -u2 -- "--chain-id is required: a signature is bound to one chain, and"
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
    acct=$(qnode query auth account "$a" --output json 2>/dev/null) || acct=""
    # WITH --via-ssh THIS MUST SUCCEED.  Returning empty makes `sign` fall back to an ONLINE
    # signature, which is the one thing the relay exists to avoid -- and it fails with a dial
    # error that names neither this lookup nor the relay.
    if [[ -z "$acct" && -n "$VIA_SSH" ]]; then
        print -u2 "could not read $a's account through $VIA_SSH -- is the node reachable there?"
        exit 1
    fi
    [[ -n "$acct" ]] || return 0
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
build-delegate)
    # STAKE IS WHAT VOTING POWER IS MADE OF.  A bucket's tokens count for nothing in a tally until
    # they are BONDED -- x/gov reads delegations, not balances (tally.go, DelegatorDeductions) --
    # and the vote is credited to the DELEGATOR, not the validator.  So a treasury that must pass
    # a proposal delegates first and votes second, and this is the first half of that.
    [[ -n "$from" && -n "$validator" && -n "$amount" && -n "$out" ]] || usage
    fa=$(addr_of "$from")
    q tx staking delegate "$validator" "$amount" \
        --from "$fa" --generate-only --chain-id "$CHAIN" --node "$NODE" \
        --gas "$GAS" --gas-prices "$GAS_PRICES" > "$out" || exit 1
    print "built $out  (delegator $fa -> $validator) -- unsigned; the sequence binds at sign"
    ;;
build-deposit)
    [[ -n "$from" && -n "$proposal" && -n "$amount" && -n "$out" ]] || usage
    fa=$(addr_of "$from")
    q tx gov deposit "$proposal" "$amount" \
        --from "$fa" --generate-only --chain-id "$CHAIN" --node "$NODE" \
        --gas "$GAS" --gas-prices "$GAS_PRICES" > "$out" || exit 1
    print "built $out  (depositor $fa, proposal $proposal) -- unsigned; the sequence binds at sign"
    ;;
build-vote)
    [[ -n "$from" && -n "$proposal" && -n "$vote_opt" && -n "$out" ]] || usage
    fa=$(addr_of "$from")
    q tx gov vote "$proposal" "$vote_opt" \
        --from "$fa" --generate-only --chain-id "$CHAIN" --node "$NODE" \
        --gas "$GAS" --gas-prices "$GAS_PRICES" > "$out" || exit 1
    print "built $out  (voter $fa, proposal $proposal = $vote_opt) -- unsigned; sequence binds at sign"
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
    # multisign reads the multisig's PUBKEY from this keyring, so it cannot be relayed -- it runs
    # here either way.  What it can do is run OFFLINE, given the same pinned account number and
    # sequence the shares were signed at, which is what makes the relay work end to end.
    if [[ -n "$VIA_SSH" ]]; then
        # THE SEQUENCE COMES FROM THE SHARES, NOT THE CHAIN.  multisign verifies each share against
        # the sequence it is told, and a share was signed at whatever the sequence was THEN plus
        # any --sequence-offset.  Reading the chain here instead makes the right answer depend on
        # whether the earlier transaction of a pair has landed yet: before it lands the shares are
        # one ahead of the chain, after it lands they match.  Getting it wrong fails with
        # "unable to verify single signer signature", which names neither the sequence nor the
        # cause.  The share records what it committed to -- use that and the question disappears.
        _ssq=$(jq -r '.signatures[0].sequence // empty' "${sigs[1]}" 2>/dev/null)
        _san=$(qnode query auth account "$(addr_of "$msig")" --output json 2>/dev/null \
               | jq -r '..|.account_number? // empty' | head -1)
        if [[ -n "$_ssq" && -n "$_san" ]]; then
            q tx multisign "$tx" "$msig" "${sigs[@]}" --chain-id "$CHAIN" \
                --offline --account-number "$_san" --sequence "$_ssq" > "$out" || exit 1
        else
            q tx multisign "$tx" "$msig" "${sigs[@]}" \
                --chain-id "$CHAIN" ${=$(seq_flags "$(addr_of "$msig")")} > "$out" || exit 1
        fi
    else
        q tx multisign "$tx" "$msig" "${sigs[@]}" \
            --chain-id "$CHAIN" --node "$NODE" > "$out" || exit 1
    fi
    n=$(jq -r '.auth_info.signer_infos[0].mode_info.multi.mode_infos | length' "$out" 2>/dev/null)
    print "combined ${#sigs} share(s) -> $out  (tx carries $n signature(s))"
    ;;
broadcast)
    [[ -n "$tx" ]] || usage
    # THE SIGNED TX GOES TO THE NODE, not the keys.  With --via-ssh it is copied there and
    # broadcast from there; it is public the instant it is sent, so this discloses nothing.
    btx="$tx"
    if [[ -n "$VIA_SSH" ]]; then
        btx="/tmp/.msig_bcast_$$.json"
        scp -q "$tx" "$VIA_SSH:$btx" || { print -u2 "could not copy $tx to $VIA_SSH"; exit 1 }
    fi
    outj=$(qnode tx broadcast "$btx" --output json 2>&1) || { print -u2 "$outj"; exit 1 }
    h=$(print "$outj" | grep '^{' | tail -1 | jq -r '.txhash // ""')
    [[ -n "$h" ]] || { print -u2 "no txhash; broadcast said:"; print -u2 "$outj"; exit 1 }

    # THE BROADCAST RESPONSE IS CheckTx, AND IT IS NOT THE ANSWER.  Default --broadcast-mode is
    # sync, so this code reflects only whether the node ACCEPTED the tx into its mempool -- not
    # whether it executed.  A tx can pass CheckTx and still fail in the block (code 1159, out of
    # gas), and it can fail CheckTx outright (bad sequence, fee below minimum) in which case it
    # will NEVER be included and polling for it just burns the timeout before reporting the wrong
    # reason.  So: a non-zero CheckTx code is a definitive rejection, reported as itself.
    ctx_code=$(print "$outj" | grep '^{' | tail -1 | jq -r '.code // 0')
    if [[ -n "$ctx_code" && "$ctx_code" != "0" ]]; then
        print -u2 "REJECTED before inclusion (CheckTx code $ctx_code) -- this tx will never land:"
        print -u2 "  $(print "$outj" | grep '^{' | tail -1 | jq -r '.raw_log // ""' | head -c 300)"
        [[ -n "$VIA_SSH" ]] && ssh -o ConnectTimeout=10 "$VIA_SSH" "rm -f $btx" 2>/dev/null
        exit 1
    fi
    print "broadcast $h"
    # POLL, DO NOT ASK ONCE.  `query wait-tx` is best-effort here (it is swallowed by `|| true`
    # so a missing subcommand cannot fail the run), and a single `query tx` straight after can
    # race inclusion: the tx is accepted, not yet in a block, the query returns nothing, and an
    # empty code reads as failure.  Observed 2026-09-01 on a grant that had in fact landed.
    qnode query wait-tx "$h" --timeout ${QADENA_TX_WAIT:-60}s > /dev/null 2>&1 || true
    code=""
    WAIT_SECS=${QADENA_TX_WAIT:-60}
    for _i in {1..$(( WAIT_SECS / 2 ))}; do
        code=$(qnode query tx "$h" --output json 2>/dev/null | jq -r '.code // ""')
        [[ -n "$code" ]] && break
        sleep 2
    done
    [[ -n "$VIA_SSH" ]] && ssh -o ConnectTimeout=10 "$VIA_SSH" "rm -f $btx" 2>/dev/null
    # THREE OUTCOMES, NOT TWO.  Conflating "not seen yet" with "failed" is how an operator gets
    # told a transaction failed when it was merely slow -- and then retries a transfer that is
    # about to land.  Exit 2 means UNKNOWN: do not retry, go and look.
    if [[ "$code" == "0" ]]; then
        print "  landed in a block, code 0 -- executed successfully"
    elif [[ -n "$code" ]]; then
        print -u2 "  EXECUTED AND FAILED, code $code:"
        qnode query tx "$h" --output json 2>/dev/null | jq -r '.raw_log' | head -c 300
        print -u2 ""
        print -u2 "  The tx IS on chain and it did not do what you wanted.  Re-signing is safe;"
        print -u2 "  the sequence it consumed is spent either way."
        exit 1
    else
        print -u2 "  UNKNOWN: accepted into the mempool, but not in a block after ${WAIT_SECS}s."
        print -u2 "  This is NOT a failure -- it may still land.  Do not re-broadcast blindly."
        print -u2 "    qadenad query tx $h"
        exit 2
    fi
    ;;
*) usage ;;
esac
