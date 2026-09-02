#!/bin/zsh
#
# Provision an account from a bucket WITHOUT stopping for a human -- test fleets only.
#
#   provision_from_bucket_local.sh --name treasury --from-bucket adoption --amount 50000000 \
#       --stake 10000000 --whitelist --host user@10.0.0.1
#
# WHY THIS IS IN testscripts/ AND NOT scripts/.  scripts/provision_account.sh prints the funding
# ceremony and WAITS, on purpose: signing for a bucket means holding that bucket's keys, and a
# script that could do it would destroy the property the multisig exists to create.  That reasoning
# is correct for a deployment and it is not negotiable there.
#
# A TEST FLEET IS THE ONE PLACE IT DOES NOT APPLY, because this workstation holds ALL FIVE member
# keys -- which is exactly the thing a real bucket must never allow.  So the automation lives here,
# clearly marked, instead of weakening the operator script.  Everything after the ceremony is
# delegated straight back to scripts/provision_account.sh, which is idempotent at every stage
# (existing key reused, "already funded" skips the ceremony, delegation skipped per validator,
# whitelist skipped if listed) -- so this adds the ceremony and borrows the rest rather than
# reimplementing it.
#
# MEANT TO BE DRIVEN BY fleet_bringup_with_tests.sh --test-local, which is what makes a whole
# launch-chain bring-up one command.  That dispatcher word-splits the command string with ${=...},
# so NO ARGUMENT HERE MAY CONTAIN A SPACE -- the reason --reason is not an option.
#
set -u
SCRIPT_DIR="${0:A:h}"
source "$SCRIPT_DIR/../scripts/setup_env.sh" > /dev/null 2>&1 || true
QBIN="${qadenabin:-$HOME/qadena/bin}/qadenad"
HOME_DIR="${QADENAHOME:-$HOME/qadena}"

NAME="" BUCKET="" AMOUNT="" STAKE="" HOST="" WHITELIST=0
NODE="${QADENA_NODE:-}" CHAIN="${QADENA_CHAIN_ID:-}"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --name)        NAME="$2"; shift 2 ;;
        --from-bucket) BUCKET="$2"; shift 2 ;;
        --amount)      AMOUNT="$2"; shift 2 ;;
        --stake)       STAKE="$2"; shift 2 ;;
        --host)        HOST="$2"; shift 2 ;;
        --whitelist)   WHITELIST=1; shift ;;
        --node)        NODE="$2"; shift 2 ;;
        --chain-id)    CHAIN="$2"; shift 2 ;;
        -h|--help)     sed -n '3,25p' "$0"; exit 0 ;;
        *) print -u2 "unknown option: $1"; exit 1 ;;
    esac
done
[[ -n "$NAME" && -n "$BUCKET" && -n "$AMOUNT" && -n "$HOST" ]] \
    || { print -u2 "need --name, --from-bucket, --amount and --host; see --help"; exit 1 }

# Derive the endpoint from --host when it was not given, so the caller repeats one address.
if [[ -z "$NODE" ]]; then NODE="tcp://${HOST##*@}:26657"; fi
if [[ -z "$CHAIN" ]]; then
    CHAIN=$(curl -s --max-time 8 "http://${HOST##*@}:26657/status" | jq -r '.result.node_info.network // empty')
    [[ -n "$CHAIN" ]] || { print -u2 "cannot reach ${HOST##*@}:26657 to learn the chain-id"; exit 1 }
fi
export QADENA_NODE="$NODE" QADENA_CHAIN_ID="$CHAIN"

kq() { ssh -o ConnectTimeout=10 "$HOST" "bash -lc '\$HOME/qadena/bin/qadenad --home \$HOME/qadena --keyring-backend test $*'" 2>/dev/null | tr -d '\r' }
q()  { "$QBIN" --home "$HOME_DIR" "$@" }
# Same measure provision_account.sh uses: liquid + delegated.  --stake spends the balance down,
# so comparing liquid alone against --amount re-runs the ceremony on an account already funded.
funded_total() {
    local liq del
    liq=$(q q bank balances "$1" --node "$NODE" --output json 2>/dev/null \
          | jq -r '[.balances[]?|select(.denom=="aqdn").amount]|first // "0"')
    del=$(q q staking delegations "$1" --node "$NODE" --output json 2>/dev/null \
          | jq -r '[.delegation_responses[]?.balance.amount]|join("+")' 2>/dev/null)
    [[ -z "$del" || "$del" == "null" ]] && del="0"
    print "${liq:-0} + $del" | bc
}
lk() { "$QBIN" --home "$HOME_DIR" --keyring-backend test "$@" }

print "provisioning $NAME from $BUCKET on $CHAIN via $NODE"

# ---------------------------------------------------------------- 1. the key, on the host
# Created HERE rather than by provision_account.sh only because the ceremony below needs the
# address first.  provision_account.sh then finds it already present and moves on.
addr=$(kq keys show "$NAME" -a)
if [[ "$addr" != qadena1* ]]; then
    print "  creating '$NAME' on $HOST"
    kq keys add "$NAME" > /dev/null 2>&1
    addr=$(kq keys show "$NAME" -a)
fi
[[ "$addr" == qadena1* ]] || { print -u2 "could not create or read $NAME on $HOST"; exit 1 }
print "  $NAME = $addr"

# ---------------------------------------------------------------- 2. the ceremony, here
want=$(print "${AMOUNT} * 1000000000000000000" | bc)
have=$(funded_total "$addr")
# Within 0.1% -- same reason as scripts/provision_account.sh: gas is spent from this balance, so
# an exact >= re-runs the ceremony on an account that is already funded.
if [[ "$have" != "0" ]] && (( $(print "$have * 1000 >= $want * 999" | bc 2>/dev/null || print 0) )); then
    print "  already funded ($have aqdn) -- skipping the ceremony"
else
    # THRESHOLD READ FROM THE KEY, not assumed.  Signing one share short produces a tx that is
    # rejected at broadcast for a reason that names the signature count and nothing else.
    thr=$(lk keys show "$BUCKET" --output json 2>/dev/null | jq -r '.pubkey | fromjson? // . | .threshold // empty')
    [[ -n "$thr" ]] || { print -u2 "$BUCKET is not a multisig key in this keyring"; exit 1 }
    print "  ceremony: $BUCKET is ${thr}-of-N, signing locally (TEST FLEET ONLY)"

    # WAIT FOR THE RPC FIRST.  Every step below needs the node: `build-send` reads the account
    # number and `sign` binds the sequence, so a momentary network fault fails ONE share and takes
    # the whole ceremony with it.  That is tolerable when a human is watching and not when this is
    # scheduled inside a 20-minute unattended fleet run -- observed exactly once, as
    # "dial tcp ...:26657: connect: no route to host" from a chain that was healthy either side of
    # it.
    print -n "  waiting for the RPC"
    for i in {1..30}; do
        curl -s --max-time 5 "http://${HOST##*@}:26657/status" > /dev/null 2>&1 && { print " -- up"; break }
        print -n "."; sleep 4
        (( i == 30 )) && { print ""; print -u2 "  ${HOST##*@}:26657 never answered"; exit 1 }
    done

    wd=$(mktemp -d)
    # ONE RETRY, from a CLEAN temp dir.  Shares bind the sequence at sign time, so a half-signed
    # set from a failed attempt cannot be topped up -- the ceremony is redone from build-send or
    # not at all.  Nothing is spent by a failed attempt: no broadcast happened.
    ceremony_ok=0
    for attempt in 1 2; do
        wd=$(mktemp -d)
        ok=1
        "$SCRIPT_DIR/../scripts/multisig_sign.sh" build-send --from "$BUCKET" --to "$addr" \
            --amount "${AMOUNT}qdn" --out "$wd/fund.json" > /dev/null || ok=0
        shares=()
        if (( ok )); then
            for i in $(seq 1 "$thr"); do
                "$SCRIPT_DIR/../scripts/multisig_sign.sh" sign --tx "$wd/fund.json" --multisig "$BUCKET" \
                    --from "${BUCKET}-m${i}" --out "$wd/s${i}.json" > /dev/null || { ok=0; break }
                shares+=("$wd/s${i}.json")
            done
        fi
        (( ok )) && { "$SCRIPT_DIR/../scripts/multisig_sign.sh" combine --tx "$wd/fund.json" \
            --multisig "$BUCKET" --out "$wd/signed.json" "${shares[@]}" > /dev/null || ok=0 }
        (( ok )) && { "$SCRIPT_DIR/../scripts/multisig_sign.sh" broadcast --tx "$wd/signed.json" || ok=0 }
        rm -rf "$wd"
        (( ok )) && { ceremony_ok=1; break }
        (( attempt == 1 )) && { print "  ceremony attempt 1 failed -- retrying in 20s"; sleep 20 }
    done
    (( ceremony_ok )) || { print -u2 "  the ceremony failed twice; nothing was broadcast"; exit 1 }

    print -n "  waiting for the coins"
    for i in {1..40}; do
        have=$(funded_total "$addr")
        [[ "$have" != "0" ]] && (( $(print "$have * 1000 >= $want * 999" | bc 2>/dev/null || print 0) )) \
            && { print " -- funded"; break }
        print -n "."; sleep 6
        (( i == 40 )) && { print ""; print -u2 "  the coins never arrived"; exit 1 }
    done
fi

# ---------------------------------------------------------------- 3. hand back to the operator script
# It sees an existing, funded key, so it skips straight to staking and the whitelist -- the parts
# that are identical on a test fleet and in production, and therefore must not be duplicated here.
args=(--name "$NAME" --from-bucket "$BUCKET" --mode banksend --amount "$AMOUNT" --host "$HOST")
[[ -n "$STAKE" ]] && args+=(--stake "$STAKE")
(( WHITELIST )) && args+=(--whitelist)
print ""
print "  handing off to scripts/provision_account.sh for stake + whitelist"
QADENA_NODE="$NODE" QADENA_CHAIN_ID="$CHAIN" "$SCRIPT_DIR/../scripts/provision_account.sh" "${args[@]}"
