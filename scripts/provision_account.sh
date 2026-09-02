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
#   ./provision_account.sh --name treasury --from-bucket adoption --mode banksend \
#       --amount 50000000 --stake 10000000 --whitelist        <- fully unattended
#
# --whitelist AND THE BOOTSTRAP TREASURY.  The whitelist is a governance proposal, and voting power
# follows BONDED stake.  A treasury that was funded thirty seconds ago has none, so it cannot vote
# itself onto the whitelist, and on a balanced fleet one operator's 25% is short of quorum.  This
# script therefore reports the proposal as LIVE and tells you what the other operators must run; it
# does not pretend the account is ready.  Until the proposal passes, the account can receive but
# cannot send to anything uncredentialed (1159).
#
# PASS --stake AND THE PROBLEM GOES AWAY.  Delegating does not require the whitelist (step 3 says
# why), so staking BEFORE the proposal gives the account the voting power to pass its own
# whitelist, and the whole provision is unattended.  Without --stake the account gets its power
# later from testscripts/setup_prerequisites.sh, which is a test script and not part of a
# production bring-up.
#
set -u
SCRIPT_DIR="${0:A:h}"
source "$SCRIPT_DIR/setup_env.sh" > /dev/null 2>&1 || true

NAME="" BUCKET="" MODE="banksend" AMOUNT="" HOST="" MNEMONIC_FILE="" WHITELIST=0 STAKE=""
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
    print "  --stake <qdn>              delegate this much BEFORE whitelisting, split evenly across"
    print "                             every bonded validator.  Voting power follows bonded stake,"
    print "                             so this is what lets --whitelist pass without other"
    print "                             operators having to vote.  banksend mode only."
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
        --stake) STAKE="$2"; shift 2 ;;
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
# What this account has RECEIVED: spendable balance plus anything it has since delegated.
funded_total() {
    local liq del
    liq=$(q q bank balances "$1" --node "$NODE" --output json 2>/dev/null \
          | jq -r '[.balances[]?|select(.denom=="aqdn").amount]|first // "0"')
    del=$(q q staking delegations "$1" --node "$NODE" --output json 2>/dev/null \
          | jq -r '[.delegation_responses[]?.balance.amount]|join("+")' 2>/dev/null)
    [[ -z "$del" || "$del" == "null" ]] && del="0"
    print "${liq:-0} + $del" | bc
}

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
    # LIQUID + DELEGATED, not liquid alone.  --stake moves coins out of the balance, so on a
    # re-run an account funded 50M and staked 10M reads 40M, looks underfunded against --amount,
    # and the ceremony is demanded a SECOND time -- which on a real bucket means a second 50M
    # actually leaving it.  Funding is about what the account received, not what it still holds.
    have=$(funded_total "$addr")
    want="${AMOUNT}000000000000000000"
    # WITHIN 0.1%, not exactly.  Gas is spent out of this same balance the moment the account does
    # anything -- and --stake makes it delegate four times before we ever look again -- so an exact
    # >= reports "underfunded" on every re-run and demands the ceremony a SECOND time, which on a
    # real bucket means the whole amount leaving it twice.  0.1% of a provisioning amount is orders
    # of magnitude above any realistic fee bill and far below a transfer that never arrived.
    if [[ "$have" != "0" ]] && (( $(print "$have * 1000 >= $want * 999" | bc 2>/dev/null || print 0) )); then
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
            have=$(funded_total "$addr")
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

# ---------------------------------------------------------------- 3. stake, so it can vote itself in
#
# ORDER MATTERS, and this is the whole reason the step exists.  The whitelist is a governance
# proposal and voting power follows BONDED stake, so an account funded thirty seconds ago has none
# and cannot vote itself onto the whitelist -- on a balanced fleet one operator's 25% is short of a
# 40% quorum, and the proposal then EXPIRES rather than failing.  Delegating first turns the
# bootstrap into an ordinary self-passing proposal.
#
# DELEGATING DOES NOT NEED THE WHITELIST, which is what makes this ordering legal.  Verified on
# chain 2026-09-02 (unwhitelisted, uncredentialed account delegated with code 0) and true for two
# independent reasons: bank's DelegateCoins moves balances directly and never calls SendCoins, so
# the SendRestrictionFn is not in the path at all; and the restriction exempts module accounts on
# either side anyway, which the staking bonded pool is.
if [[ -n "$STAKE" ]]; then
    if [[ "$MODE" != "banksend" ]]; then
        print -u2 "--stake needs coins to delegate; it is meaningless with --mode feegrant"
        exit 1
    fi
    valopers=($(q q staking validators --node "$NODE" --output json 2>/dev/null \
        | jq -r '.validators[]?|select(.status=="BOND_STATUS_BONDED")|.operator_address'))
    if (( ${#valopers[@]} == 0 )); then
        print -u2 "no bonded validators to delegate to"
        exit 1
    fi
    # SPLIT, NEVER CONCENTRATE.  The whole delegation on one validator also hands it >2/3 of
    # CONSENSUS power, which lets it finalise blocks alone -- a peer that disagrees prevotes nil and
    # is outvoted.  That is not hypothetical on this chain; see the note at
    # testscripts/setup_prerequisites.sh:278.  Governance is unaffected by splitting, because a
    # delegator's voting power is the SUM of its delegations across every validator.
    share=$(( ${STAKE%qdn} / ${#valopers[@]} ))
    if (( share <= 0 )); then
        print -u2 "$STAKE split ${#valopers[@]} ways rounds to zero"
        exit 1
    fi
    print ""
    print "  delegating ${STAKE%qdn}qdn as ${share}qdn to each of ${#valopers[@]} validator(s)"
    for v in "${valopers[@]}"; do
        # per-validator, so re-running after another validator joins tops up the newcomer
        already=$(q q staking delegation "$addr" "$v" --node "$NODE" --output json 2>/dev/null \
            | jq -r '.delegation_response.balance.amount // "0"' 2>/dev/null) || already="0"
        if [[ "${already:-0}" != "0" ]]; then
            print "    $v: already delegated, skipping"
            continue
        fi
        # CONFIRM EACH ONE BEFORE SENDING THE NEXT.  These go from a single account, so every tx
        # needs the following sequence number -- fired back to back they land in the same block,
        # the sequence has not advanced, and CheckTx rejects the later ones.  qadenad still EXITS
        # 0 (the tx was accepted for broadcast, not for inclusion), so without reading the code
        # back the loop reports four delegations and the chain records two.  Observed exactly
        # that: 2 of 4, then 1 of 2.
        out=$(kq tx staking delegate "$v" "${share}qdn" --from "$NAME" --node "$NODE" \
            --chain-id "$CHAIN" -y --output json --gas auto --gas-adjustment 1.5 \
            --gas-prices "${minimum_gas_prices:-500000000aqdn}")
        # sed, not jq: qadenad prints "gas estimate: N" before the JSON, so parsing the whole
        # stream as JSON fails on a transaction that was in fact broadcast.
        h=$(print "$out" | sed -n 's/.*"txhash":"\([0-9A-Fa-f]*\)".*/\1/p' | head -1)
        [[ -n "$h" ]] || { print -u2 "    $v: no txhash returned"; print -u2 "$out" | tail -3; exit 1 }
        code=""
        for w in {1..20}; do
            code=$(q q tx "$h" --node "$NODE" --output json 2>/dev/null | jq -r '.code // empty')
            [[ -n "$code" ]] && break
            sleep 3
        done
        [[ "$code" == "0" ]] || { print -u2 "    $v: delegation $h did not land (code ${code:-none})"; exit 1 }
        print "    $v: ${share}qdn"
    done
    # WAIT FOR ALL OF THEM, not merely one.  Voting power is the SUM across validators, so
    # proceeding at the first delegation would submit the whitelist proposal with a fraction of
    # the intended stake -- and a proposal short of quorum expires rather than failing.
    print -n "  waiting for ${#valopers[@]} delegation(s) to register"
    for i in {1..30}; do
        d=$(q q staking delegations "$addr" --node "$NODE" --output json 2>/dev/null \
            | jq -r '[.delegation_responses[]?]|length' 2>/dev/null)
        [[ "${d:-0}" -ge ${#valopers[@]} ]] && { print " -- ${d}"; break }
        print -n "."; sleep 6
        (( i == 30 )) && { print ""; print -u2 "only ${d:-0} of ${#valopers[@]} delegations registered"; exit 1 }
    done
fi

# ---------------------------------------------------------------- 4. governance, if it must send
if (( WHITELIST )); then
    listed=$(q q qadena list-scanned-contract-whitelist --node "$NODE" --output json 2>/dev/null \
             | jq -r --arg a "$addr" '[.scannedContractWhitelist[]?|select(.address==$a)]|length' 2>/dev/null)
    if [[ "${listed:-0}" -gt 0 ]]; then
        print "  already on the scanned-contract whitelist"
    else
        print ""
        print "  whitelisting by governance (proposal, deposit, vote -- takes a voting period)"
        # RUN IT WHERE THE PROPOSER'S KEY AND MONEY ARE.  The deposit is paid by $NAME itself,
        # which with --host lives on that machine and not on this one.  Running it locally against
        # a same-named key that has no on-chain account fails with "account ... not found", which
        # reads like a chain problem and is not one.
        #
        # scripts/, NOT testscripts/whitelist_bank_send.sh.  That fixture votes only through
        # gov_vote_from_treasury.sh, which carries ~99% of stake on the DEVNET and exactly ZERO on
        # a launch chain, where the treasury is a funded key with no delegations.  Its vote lands
        # with code 0 and the proposal then EXPIRES rather than failing.  See the header of
        # scripts/gov_whitelist_bank_send.sh.
        #
        # Exit 2 is NOT a failure: it means the proposal is live and voted, and needs operators
        # this node cannot vote for.  Bootstrapping a treasury always lands here on a balanced
        # fleet, because nothing has delegated to it yet -- so it cannot vote itself in.
        # VOTE AS $NAME when it was just staked -- it is the account that now holds the power.
        # Left to its default the helper votes as this node's operator, which on a balanced fleet
        # is 25% against a 40% quorum and lands in the exit-2 path for no reason.
        wlargs=(--from "$NAME" --reason "provisioned from $BUCKET" "$addr")
        [[ -n "$STAKE" ]] && wlargs+=("$NAME")
        if [[ -n "$HOST" ]]; then
            # ${(q)...} QUOTES EACH ELEMENT.  A bare ${wlargs[*]} flattens the array into one
            # string, so --reason "provisioned from adoption" arrives as three words: --reason
            # takes "provisioned", and "from" is then read as the ADDRESS.  The error that
            # produces -- "from is neither a bech32 address nor a key in this keyring" -- names
            # the symptom and nothing else.
            ssh -o ConnectTimeout=10 "$HOST" \
                "bash -lc 'cd \$HOME/qv3 && ./scripts/gov_whitelist_bank_send.sh ${(j: :)${(q)wlargs[@]}}'"
        else
            "$SCRIPT_DIR/gov_whitelist_bank_send.sh" "${wlargs[@]}"
        fi
        case $? in
            0) : ;;
            2) print ""
               print "  $NAME IS FUNDED BUT NOT YET WHITELISTED -- the proposal above is live and"
               print "  needs more operators to vote.  Until it passes, $NAME cannot send to any"
               print "  address that holds no credential (code 1159)."
               ;;
            *) print -u2 "the whitelist proposal could not be submitted; $NAME cannot send to unidentified addresses"
               exit 1 ;;
        esac
    fi
fi

print ""
print "DONE.  $NAME = $addr"
