#!/bin/zsh
#
# Regression test for transfer -> queue -> receive.
#
# The property under test: transferred funds land in the DESTINATION EPHEMERAL WALLET and stay
# there until the owner of the linked real wallet receives them.  The eph wallet is the queue.
# Three ways that can go wrong, and this script checks all three:
#
#   1. funds do not arrive in the destination eph wallet at all
#   2. funds arrive but are credited straight to the real wallet, skipping the queue -- which would
#      defeat the whole receive step
#   3. funds arrive in the WRONG eph wallet -- users have several (ann-eph1, ann-eph2, ...), so
#      "it showed up somewhere in ann's wallets" is not good enough
#
# Assertions are on ENCRYPTED balances, which are exact: transaction fees come out of the
# transparent balance, so the encrypted side moves by precisely the transferred amount.  Everything
# is a DELTA against a reading taken at the start, so the script is re-runnable -- absolute balances
# differ every run.
#
# Run AFTER testscripts/setup.sh.

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

# set -e after the source: setup_env.sh queries the chain and falls back on failure
set -e

function qadenad_alias { "$qadenabin/qadenad" --home "$QADENAHOME" "$@" }

amount="100"          # qdn, encrypted
second_amount="25"    # qdn, encrypted, for the wrong-queue check

fail() {
    echo "FAILED: $1"
    exit 1
}

addr_of() {
    qadenad_alias keys show "$1" -a --keyring-backend test 2>/dev/null
}

# encrypted balance of a wallet, as a plain decimal string.  show-wallet colourises its output, so
# the ANSI escapes have to come off before parsing.
#
# Takes the FIRST "Encrypted balance" line, which is the head of the wallet's list: the actual
# balance for a real wallet, and for an ephemeral one the entry the next receive-funds will take.
# Not a total -- an eph wallet's queue is several distinct pending transfers and summing them would
# hide which one moved.
#
# The limitation to know: a transfer into an eph wallet that ALREADY holds something is appended
# BEHIND the head (see the EphemeralWalletAmountCount branches in cmd/qadenad_enclave/enclave.go),
# so this reading would not move.  Every case below starts from a drained eph wallet, which is why
# the receive-funds calls between cases are load-bearing -- a test that leaves one undrained breaks
# the next run rather than its own.
enc_balance() {
    local addr
    addr=$(addr_of "$1") || { echo ""; return; }
    qadenad_alias query qadena show-wallet "$addr" --decrypt-as "$addr" 2>/dev/null \
        | perl -pe 's/\e\[[0-9;]*m//g' \
        | sed -n 's/^Encrypted balance \([0-9.]*\)qdn.*/\1/p' | head -1
}

wallet_type() {
    local addr
    addr=$(addr_of "$1") || { echo ""; return; }
    qadenad_alias query qadena show-wallet "$addr" --decrypt-as "$addr" 2>/dev/null \
        | perl -pe 's/\e\[[0-9;]*m//g' \
        | sed -n 's/^Wallet Type: *\(.*\)$/\1/p' | head -1
}

# delta_is <before> <after> <expected>  -- decimal-safe comparison
delta_is() {
    python3 -c "
from decimal import Decimal
b,a,e = Decimal('$1'), Decimal('$2'), Decimal('$3')
raise SystemExit(0 if (a-b) == e else 1)
"
}

delta_of() {
    python3 -c "from decimal import Decimal; print(Decimal('$2')-Decimal('$1'))"
}

echo "========================="
echo "preflight"
echo "========================="
qadenad_alias status > /dev/null 2>&1 || fail "chain is not reachable -- start it first"
for w in al ann ann-eph1 ann-eph2 victor; do
    addr_of "$w" > /dev/null 2>&1 || fail "$w not in the keyring -- run testscripts/setup.sh first"
done

# the test is meaningless if these are not the wallet kinds we think they are
case "$(wallet_type ann)" in
    Primary*) ;;
    *) fail "ann is not a Primary wallet: $(wallet_type ann)" ;;
esac
case "$(wallet_type ann-eph1)" in
    Ephemeral*) ;;
    *) fail "ann-eph1 is not an Ephemeral wallet: $(wallet_type ann-eph1)" ;;
esac
echo "chain up; ann is Primary, ann-eph1 is Ephemeral"

al_before=$(enc_balance al)
ann_before=$(enc_balance ann)
eph1_before=$(enc_balance ann-eph1)
eph2_before=$(enc_balance ann-eph2)
[ -n "$al_before" ] && [ -n "$ann_before" ] && [ -n "$eph1_before" ] && [ -n "$eph2_before" ] \
    || fail "could not read starting encrypted balances"

echo "start:  al=$al_before  ann=$ann_before  ann-eph1=$eph1_before  ann-eph2=$eph2_before"

echo "========================="
echo "1. transfer al -> ann-eph1 lands in the queue"
echo "========================="
qadenad_alias tx qadena transfer-funds ann-eph1 "${amount}qdn" 0qdn \
    --transfer-note "regression test transfer" --from al --yes > /dev/null \
    || fail "transfer-funds failed"

al_after=$(enc_balance al)
eph1_after=$(enc_balance ann-eph1)
echo "al:       $al_before -> $al_after   (delta $(delta_of "$al_before" "$al_after"))"
echo "ann-eph1: $eph1_before -> $eph1_after   (delta $(delta_of "$eph1_before" "$eph1_after"))"

delta_is "$eph1_before" "$eph1_after" "$amount" \
    || fail "ann-eph1 gained $(delta_of "$eph1_before" "$eph1_after"), expected exactly $amount"
delta_is "$al_before" "$al_after" "-$amount" \
    || fail "al lost $(delta_of "$al_before" "$al_after"), expected exactly -$amount"

echo "========================="
echo "2. the funds are QUEUED, not yet credited to the real wallet"
echo "========================="
# this is the assertion the whole design rests on: until ann receives, her real wallet must not see
# the money.  If this ever passes silently, the receive step has become decorative.
ann_mid=$(enc_balance ann)
echo "ann (real): $ann_before -> $ann_mid"
delta_is "$ann_before" "$ann_mid" "0" \
    || fail "ann's real wallet changed by $(delta_of "$ann_before" "$ann_mid") before receive-funds was called"
echo "ann's real wallet untouched, as expected"

echo "========================="
echo "3. the funds are in the CORRECT queue, not just some queue of ann's"
echo "========================="
eph2_mid=$(enc_balance ann-eph2)
echo "ann-eph2: $eph2_before -> $eph2_mid"
delta_is "$eph2_before" "$eph2_mid" "0" \
    || fail "ann-eph2 changed by $(delta_of "$eph2_before" "$eph2_mid"); the transfer went to the wrong eph wallet"
echo "ann-eph2 untouched"

echo "========================="
echo "4. receive-funds drains the queue into the real wallet"
echo "========================="
# 0qdn = convert none of it to transparent, i.e. keep the whole amount encrypted
qadenad_alias tx qadena receive-funds ann-eph1 0qdn --from ann --yes > /dev/null \
    || fail "receive-funds failed"

eph1_final=$(enc_balance ann-eph1)
ann_final=$(enc_balance ann)
echo "ann-eph1: $eph1_after -> $eph1_final"
echo "ann:      $ann_mid -> $ann_final"

delta_is "$eph1_after" "$eph1_final" "-$amount" \
    || fail "ann-eph1 released $(delta_of "$eph1_after" "$eph1_final"), expected -$amount"
delta_is "$ann_mid" "$ann_final" "$amount" \
    || fail "ann received $(delta_of "$ann_mid" "$ann_final"), expected exactly $amount"

echo "========================="
echo "5. a second transfer to a DIFFERENT eph wallet queues independently"
echo "========================="
# proves the queues are per-eph-wallet rather than pooled per user
qadenad_alias tx qadena transfer-funds ann-eph2 "${second_amount}qdn" 0qdn \
    --transfer-note "regression test second transfer" --from al --yes > /dev/null \
    || fail "second transfer-funds failed"

eph1_check=$(enc_balance ann-eph1)
eph2_final=$(enc_balance ann-eph2)
echo "ann-eph2: $eph2_mid -> $eph2_final"
echo "ann-eph1: $eph1_final -> $eph1_check"

delta_is "$eph2_mid" "$eph2_final" "$second_amount" \
    || fail "ann-eph2 gained $(delta_of "$eph2_mid" "$eph2_final"), expected $second_amount"
delta_is "$eph1_final" "$eph1_check" "0" \
    || fail "ann-eph1 changed while transferring to ann-eph2; the queues are not independent"

echo "========================="
echo "6. only the linked owner may drain a queue"
echo "========================="
# victor is not linked to ann-eph2, so his receive must be refused.  --gas auto makes the CLI
# simulate first, so an execution failure surfaces as a non-zero exit before broadcast.
if qadenad_alias tx qadena receive-funds ann-eph2 0qdn --from victor --yes > /dev/null 2>&1; then
    fail "victor is not linked to ann-eph2 but his receive-funds succeeded"
fi
echo "rejected as expected"

# and prove it by state, not just by the exit code
eph2_check=$(enc_balance ann-eph2)
delta_is "$eph2_final" "$eph2_check" "0" \
    || fail "ann-eph2 changed by $(delta_of "$eph2_final" "$eph2_check") after victor's rejected receive"
echo "ann-eph2 still holds $eph2_check"

echo "========================="
echo "7. ann drains the second queue"
echo "========================="
qadenad_alias tx qadena receive-funds ann-eph2 0qdn --from ann --yes > /dev/null \
    || fail "receive-funds from ann-eph2 failed"

eph2_end=$(enc_balance ann-eph2)
ann_end=$(enc_balance ann)
delta_is "$eph2_final" "$eph2_end" "-$second_amount" \
    || fail "ann-eph2 released $(delta_of "$eph2_final" "$eph2_end"), expected -$second_amount"
delta_is "$ann_final" "$ann_end" "$second_amount" \
    || fail "ann received $(delta_of "$ann_final" "$ann_end"), expected $second_amount"

al_end=$(enc_balance al)
echo "-------------------------"
echo "net: al $(delta_of "$al_before" "$al_end")  ann +$(delta_of "$ann_before" "$ann_end")  both queues drained"
echo "-------------------------"
# the two sides must agree: everything al sent, ann received
python3 -c "
from decimal import Decimal
a = Decimal('$al_end') - Decimal('$al_before')
b = Decimal('$ann_end') - Decimal('$ann_before')
raise SystemExit(0 if -a == b else 1)
" || fail "al sent $(delta_of "$al_before" "$al_end") but ann received $(delta_of "$ann_before" "$ann_end") -- funds were created or destroyed"
echo "conservation holds: what al sent is exactly what ann received"

echo "========================="
echo "TRANSFER / RECEIVE TESTS PASSED"
echo "========================="
