#!/bin/zsh
#
# Create an account and pay for it OUT OF A BUCKET -- the launch chain's way of doing what
# `tx bank send treasury ...` does on the devnet.
#
# WHAT THIS IS FOR.  A deployment needs named accounts: foundation-appsvr, foundation-users, a
# per-deployment treasury, the `treasury` the regression suites expect.  testscripts/
# setup_veritas.sh creates its own from hardcoded mnemonics and funds them from `treasury`, which
# works on the devnet because that key exists there and the primary holds it.
#
# A LAUNCH CHAIN HAS NO SUCH KEY.  Its money is in bucket multisigs (adoption, grants, nodeops...)
# whose members are on other machines by design.  So funding is not something a script can just
# do -- it is a CEREMONY, and this prepares it, prints it, and waits for the result.  A script
# that could sign for the bucket would have to hold the bucket's keys, which is the property the
# multisig exists to prevent.
#
# TWO MODES, and the choice is about what the account is FOR:
#
#   --mode feegrant   No coins move.  The bucket pays this account's FEES, forever, bounded by a
#                     period budget.  The account holds NOTHING and cannot move value -- right
#                     for an agent that only signs (an appsvr, a signing service).  Nothing to
#                     steal, nothing stranded.
#   --mode banksend   Real coins.  Right when the account must HOLD value -- stake, a float it
#                     spends down, a treasury other things draw on.
#
# --whitelist ADDS A GOVERNANCE STEP, and you need it more often than you would think.  A fresh
# key holds no eKYC credential, so it may RECEIVE from a whitelisted bucket (the onboarding rule)
# but may not SEND to any address that is itself unidentified -- code 1159.  An account that pays
# other fresh accounts (a treasury, a faucet) therefore has to be listed by governance first.
# One that only receives, or only ever pays credentialed wallets, does not.
#
#   ./provision_account.sh --name foundation-appsvr --from-bucket adoption --mode feegrant
#   ./provision_account.sh --name treasury --from-bucket adoption --mode banksend \
#       --amount 50000000 --whitelist
#
set -u
SCRIPT_DIR="${0:A:h}"
source "$SCRIPT_DIR/setup_env.sh" > /dev/null 2>&1 || true

NAME="" BUCKET="" MODE="banksend" AMOUNT="" HOST="" MNEMONIC_FILE="" WHITELIST=0
PERIOD="2592000" PERIOD_LIMIT="1000qdn" MSGS=""
NODE="${QADENA_NODE:-tcp://localhost:26657}"
CHAIN="${QADENA_CHAIN_ID:-}"

usage() {
    print "Usage: provision_account.sh --name <key> --from-bucket <bucket> [options]"
    print ""
    print "  --mode banksend|feegrant   coins, or fees-only (default banksend)"
    print "  --amount <qdn>             banksend: how much"
    print "  --period / --period-limit  feegrant: budget window (default 30d / 1000qdn)"
    print "  --msgs <csv>               feegrant: allowed message types (default: all, unbounded)"
    print "  --whitelist                also list it by governance.  REQUIRED if this account will"
    print "                             SEND to addresses that hold no credential."
    print "  --host <user@ip>           create the key there instead of locally (e.g. the node that"
    print "                             will use it).  The key never leaves that machine."
    print "  --mnemonic-file <f>        recover a KNOWN key instead of minting a new one, so the"
    print "                             address is stable across rebuilds (setup_veritas.sh's"
    print "                             accounts work this way)."
    print "  --node / --chain-id        RPC and chain (default \$QADENA_NODE / \$QADENA_CHAIN_ID)"
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --name) NAME="$2"; shift 2 ;;
        --from-bucket) BUCKET="$2"; shift 2 ;;
        --mode) MODE="$2"; shift 2 ;;
        --amount) AMOUNT="$2"; shift 2 ;;
        --period) PERIOD="$2"; shift 2 ;;
        --period-limit) PERIOD_LIMIT="$2"; shift 2 ;;
        --msgs) MSGS="$2"; shift 2 ;;
        --whitelist) WHITELIST=1; shift ;;
        --host) HOST="$2"; shift 2 ;;
        --mnemonic-file) MNEMONIC_FILE="$2"; shift 2 ;;
        --node) NODE="$2"; shift 2 ;;
        --chain-id) CHAIN="$2"; shift 2 ;;
        --help|-h) usage ;;
        *) print -u2 "unknown option: $1"; exit 1 ;;
    esac
done
[[ -n "$NAME" && -n "$BUCKET" ]] || { print -u2 "--name and --from-bucket are required"; usage }
[[ "$MODE" == "banksend" || "$MODE" == "feegrant" ]] || { print -u2 "--mode must be banksend or feegrant"; exit 1 }
[[ "$MODE" == "banksend" && -z "$AMOUNT" ]] && { print -u2 "--mode banksend needs --amount"; exit 1 }
[[ -n "$CHAIN" ]] || { print -u2 "--chain-id is required (or set QADENA_CHAIN_ID)"; exit 1 }

QBIN="${qadenabin:-$HOME/qadena/bin}/qadenad"
HOME_DIR="${QADENAHOME:-$HOME/qadena}"
# Run key operations wherever the key is meant to LIVE.  Its privacy is the whole point: a key
# created on the node that uses it never crosses the network at all.
kq() {
    if [[ -n "$HOST" ]]; then
        ssh -o ConnectTimeout=10 "$HOST" "bash -lc '\$HOME/qadena/bin/qadenad --home \$HOME/qadena --keyring-backend test $*'" 2>/dev/null | tr -d '\r'
    else
        "$QBIN" --home "$HOME_DIR" --keyring-backend test "$@" 2>/dev/null
    fi
}
q() { "$QBIN" --home "$HOME_DIR" "$@"; }

# ---------------------------------------------------------------- 1. the key
addr=$(kq keys show "$NAME" -a)
if [[ "$addr" != qadena1* ]]; then
    if [[ -n "$MNEMONIC_FILE" ]]; then
        [[ -f "$MNEMONIC_FILE" ]] || { print -u2 "$MNEMONIC_FILE does not exist"; exit 1 }
        print "recovering '$NAME' from $MNEMONIC_FILE"
        if [[ -n "$HOST" ]]; then
            scp -q "$MNEMONIC_FILE" "$HOST:/tmp/.pa_mn" || { print -u2 "cannot copy the mnemonic"; exit 1 }
            ssh "$HOST" "bash -lc 'cat /tmp/.pa_mn | \$HOME/qadena/bin/qadenad --home \$HOME/qadena keys add $NAME --recover --keyring-backend test >/dev/null 2>&1; rm -f /tmp/.pa_mn'"
        else
            cat "$MNEMONIC_FILE" | "$QBIN" --home "$HOME_DIR" keys add "$NAME" --recover --keyring-backend test > /dev/null 2>&1
        fi
    else
        print "creating '$NAME'${HOST:+ on $HOST}"
        kq keys add "$NAME" > /dev/null 2>&1
    fi
    addr=$(kq keys show "$NAME" -a)
    [[ "$addr" == qadena1* ]] || { print -u2 "could not create/recover $NAME"; exit 1 }
fi
print "  $NAME = $addr"
print "  chain  = $CHAIN   bucket = $BUCKET   mode = $MODE"

# ---------------------------------------------------------------- 2. the ceremony
bucket_addr=$(q keys show "$BUCKET" -a --keyring-backend test 2>/dev/null)
[[ -n "$bucket_addr" ]] && bucket_note="$BUCKET ($bucket_addr)" || bucket_note="$BUCKET"

if [[ "$MODE" == "banksend" ]]; then
    have=$(q q bank balances "$addr" --node "$NODE" --output json 2>/dev/null \
           | jq -r '[.balances[]?|select(.denom=="aqdn").amount]|first // "0"')
    want="${AMOUNT}000000000000000000"
    if [[ "$have" != "0" ]] && (( $(print "$have >= $want" | bc 2>/dev/null || print 0) )); then
        print "  already funded ($have aqdn) -- no ceremony needed"
    else
        print ""
        print "=== $bucket_note MUST SIGN ======================================================="
        print "  export QADENA_NODE=$NODE QADENA_CHAIN_ID=$CHAIN"
        print "  scripts/multisig_sign.sh build-send --from $BUCKET --to $addr --amount ${AMOUNT}qdn --out fund.json"
        print "  # once PER MEMBER, on that member's own machine:"
        print "  scripts/multisig_sign.sh sign --tx fund.json --multisig $BUCKET --from ${BUCKET}-mN --out sN.json"
        print "  scripts/multisig_sign.sh combine --tx fund.json --multisig $BUCKET --out signed.json s1.json s2.json s3.json"
        print "  scripts/multisig_sign.sh broadcast --tx signed.json"
        print ""
        print "  This lands in a credential-less address only because $BUCKET is whitelisted --"
        print "  a whitelisted sender may fund an unidentified one.  THE REVERSE IS NOT TRUE:"
        print "  these coins cannot be sent back out (1159) unless step 3 lists this account."
        print "================================================================================="
        print -n "  waiting"
        for i in {1..240}; do
            have=$(q q bank balances "$addr" --node "$NODE" --output json 2>/dev/null \
                   | jq -r '[.balances[]?|select(.denom=="aqdn").amount]|first // "0"')
            [[ "$have" != "0" ]] && (( $(print "$have >= $want" | bc 2>/dev/null || print 0) )) \
                && { print " -- funded"; break }
            print -n "."; sleep 15
            (( i == 240 )) && { print ""; print -u2 "gave up after an hour"; exit 1 }
        done
    fi
else
    n=$(q q feegrant grants-by-grantee "$addr" --node "$NODE" --output json 2>/dev/null | jq -r '.allowances|length' 2>/dev/null)
    if [[ "${n:-0}" -gt 0 ]]; then
        print "  already has a fee grant -- no ceremony needed"
    else
        msg_arg=""
        [[ -n "$MSGS" ]] && msg_arg=" --msgs '$MSGS'"
        print ""
        print "=== $bucket_note MUST SIGN ======================================================="
        print "  export QADENA_NODE=$NODE QADENA_CHAIN_ID=$CHAIN"
        print "  scripts/multisig_sign.sh build-feegrant --granter $BUCKET --grantee $addr \\"
        print "      --period $PERIOD --period-limit $PERIOD_LIMIT$msg_arg --out grant.json"
        print "  scripts/multisig_sign.sh sign --tx grant.json --multisig $BUCKET --from ${BUCKET}-mN --out sN.json"
        print "  scripts/multisig_sign.sh combine --tx grant.json --multisig $BUCKET --out signed.json s1.json s2.json s3.json"
        print "  scripts/multisig_sign.sh broadcast --tx signed.json"
        print ""
        print "  NO COINS MOVE.  $NAME will hold nothing and pay no fees of its own."
        print "  Scope --msgs to what it actually sends: an unbounded grant lets a compromised"
        print "  key spend the bucket's balance on gas for anything it likes."
        print "================================================================================="
        print -n "  waiting"
        for i in {1..240}; do
            n=$(q q feegrant grants-by-grantee "$addr" --node "$NODE" --output json 2>/dev/null | jq -r '.allowances|length' 2>/dev/null)
            [[ "${n:-0}" -gt 0 ]] && { print " -- granted"; break }
            print -n "."; sleep 15
            (( i == 240 )) && { print ""; print -u2 "gave up after an hour"; exit 1 }
        done
    fi
fi

# ---------------------------------------------------------------- 3. governance, if it must send
if (( WHITELIST )); then
    listed=$(q q qadena list-scanned-contract-whitelist --node "$NODE" --output json 2>/dev/null \
             | jq -r --arg a "$addr" '[.scannedContractWhitelist[]?|select(.address==$a)]|length' 2>/dev/null)
    if [[ "${listed:-0}" -gt 0 ]]; then
        print "  already on the scanned-contract whitelist"
    else
        print ""
        print "  whitelisting by governance (proposal, deposit, vote -- takes a voting period)"
        # RUN IT WHERE THE PROPOSER'S KEY AND MONEY ARE.  whitelist_bank_send.sh submits
        # `--from treasury` and pays a deposit, so it must run on the machine whose keyring holds
        # a FUNDED treasury -- which, with --host, is that machine and not this one.  Running it
        # locally against a same-named key that has no on-chain account fails with
        # "account ... not found", which reads like a chain problem and is not one.
        if [[ -n "$HOST" ]]; then
            ssh -o ConnectTimeout=10 "$HOST" \
                "bash -lc 'cd \$HOME/qv3 && ./testscripts/whitelist_bank_send.sh $addr \"provisioned from $BUCKET\"'" \
                || { print -u2 "the proposal did not pass; $NAME cannot send to unidentified addresses"; exit 1 }
        else
            "$SCRIPT_DIR/../testscripts/whitelist_bank_send.sh" "$addr" "provisioned from $BUCKET" \
                || { print -u2 "the proposal did not pass; $NAME cannot send to unidentified addresses"; exit 1 }
        fi
    fi
fi

print ""
print "DONE.  $NAME = $addr"
