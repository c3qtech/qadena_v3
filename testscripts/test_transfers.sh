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
echo "8. an EPHEMERAL wallet can itself be the source of a transfer"
echo "========================="
# Everything above sends from a primary wallet.  Nothing in the transfer path restricts the sender
# by wallet type -- only the DESTINATION must be ephemeral (tx_transfer_funds.go rejects a real
# dst-wallet-id, and the enclave rejects it again) -- so an eph wallet sending onward is legal, and
# this pins that down.
#
# Two dedicated eph wallets, both linked to al, so the hop is self-contained: al funds the first,
# the first pays the second, and al collects from both.  al nets zero, which is what keeps this
# repeatable -- the cases above permanently move funds from al to ann, so a case that also drained
# al would shorten how many times the suite can run.
#
# They link to al specifically because al holds a credential.  The AML scan picks the reporting
# threshold from the sender's residency and citizenship, resolved through the sender's LINKED REAL
# wallet, so an eph wallet whose owner has no credential is refused outright (see test_suspicious.sh
# case 10).  That resolution is itself worth exercising: it only works if the enclave follows the
# eph -> real link rather than looking at the eph wallet.
eph_src="al-ephsrc"
eph_dst="al-ephdst"
# Kept small on purpose.  al's encrypted balance is never replenished -- cases 1-7 move funds to ann
# permanently -- so the suite has a finite number of runs in it, and this case should not shorten
# that.  It nets zero for al, and asking for little means it still runs when al is nearly out.
send_to_eph="20"
eph_hop="10"

# idempotent: create only if absent.  Fixed names rather than per-run ones, so repeated runs reuse
# the same pair instead of littering the keyring.
for w in "$eph_src:7" "$eph_dst:8"; do
    name="${w%%:*}"
    idx="${w##*:}"
    if ! addr_of "$name" > /dev/null 2>&1; then
        qadenad_alias tx qadena create-wallet "$name" pioneer1 create-wallet-sponsor \
            --link-to-real-wallet al --eph-account-index "$idx" --yes > /dev/null \
            || fail "could not create $name"
        echo "created $name"
    fi
done

src_before=$(enc_balance "$eph_src")
dst_before=$(enc_balance "$eph_dst")

qadenad_alias tx qadena transfer-funds "$eph_src" "${send_to_eph}qdn" 0qdn \
    --transfer-note "funding an eph source" --from al --yes > /dev/null \
    || fail "could not fund $eph_src from al"

src_funded=$(enc_balance "$eph_src")
delta_is "$src_before" "$src_funded" "$send_to_eph" \
    || fail "$eph_src gained $(delta_of "$src_before" "$src_funded"), expected $send_to_eph"
echo "$eph_src funded with ${send_to_eph}qdn"

echo "-------------------------"
echo "$eph_src -> $eph_dst: the sender here is an ephemeral wallet"
echo "-------------------------"
qadenad_alias tx qadena transfer-funds "$eph_dst" "${eph_hop}qdn" 0qdn \
    --transfer-note "eph wallet as source" --from "$eph_src" --yes > /dev/null \
    || fail "an ephemeral wallet was refused as the source of a transfer"

src_after=$(enc_balance "$eph_src")
dst_after=$(enc_balance "$eph_dst")
echo "$eph_src: $src_funded -> $src_after"
echo "$eph_dst: $dst_before -> $dst_after"

delta_is "$src_funded" "$src_after" "-$eph_hop" \
    || fail "$eph_src released $(delta_of "$src_funded" "$src_after"), expected -$eph_hop"
delta_is "$dst_before" "$dst_after" "$eph_hop" \
    || fail "$eph_dst gained $(delta_of "$dst_before" "$dst_after"), expected $eph_hop"

echo "-------------------------"
echo "al collects from both, so this case leaves no residue"
echo "-------------------------"
# Draining matters here for the same reason as everywhere else in this file: an eph wallet left
# holding something makes the NEXT run's transfer queue behind it instead of landing at the head,
# and the assertions above would then read a stale entry.
qadenad_alias tx qadena receive-funds "$eph_dst" 0qdn --from al --yes > /dev/null \
    || fail "al could not receive from $eph_dst"
qadenad_alias tx qadena receive-funds "$eph_src" 0qdn --from al --yes > /dev/null \
    || fail "al could not receive from $eph_src"
echo "both drained"

echo "========================="
echo "9. transfers come back in the order they arrived"
echo "========================="
# Two properties, neither of which any other case in this file reaches.
#
# Every case above moves ONE transfer and drains it -- the only depth at which the queue behaves
# simply.  An ephemeral wallet keeps its pending transfers in two places (walletAmount holds the
# head, queuedWalletAmount the rest) and pins its own creation commitment at the TAIL of the queue,
# so transfers are inserted ahead of it.  Get that wrong and the commitment drifts into the middle,
# where a receive consumes it and delivers nothing while a real transfer is left behind that
# receive-funds then refuses.
#
# Conservation would not catch that: an ephemeral wallet can also be the SOURCE of a transfer, so a
# leftover entry is still spendable and no value is lost.  What fails is the ORDER and the emptying,
# which is what 9b measures directly -- distinct amounts, so each receive is identifiable.
eph_drain="al-ephdrain"

if ! addr_of "$eph_drain" > /dev/null 2>&1; then
    qadenad_alias tx qadena create-wallet "$eph_drain" pioneer1 create-wallet-sponsor \
        --link-to-real-wallet al --eph-account-index 9 --yes > /dev/null \
        || fail "could not create $eph_drain"
    echo "created $eph_drain"
fi

# Start from a known-empty wallet: anything a previous run left behind would queue ahead of these
# and be counted as one of them.
for _ in {1..12}; do
    qadenad_alias tx qadena receive-funds "$eph_drain" 0qdn --from al --yes > /dev/null 2>&1 || break
done

echo "-------------------------"
echo "9a. a single transfer still works"
echo "-------------------------"
# The N=1 path is the one the rest of this suite depends on, and it goes through a different branch
# from N>1: with nothing pending, the transfer becomes the head and displaces the creation
# commitment into the queue.  Worth asserting on its own so a change aimed at deeper queues cannot
# quietly break the common case.
single_amount="7"
al_pre_single=$(enc_balance al)

qadenad_alias tx qadena transfer-funds "$eph_drain" "${single_amount}qdn" 0qdn \
    --transfer-note "single transfer" --from al --yes > /dev/null \
    || fail "single transfer to $eph_drain failed"
qadenad_alias tx qadena receive-funds "$eph_drain" 0qdn --from al --yes > /dev/null \
    || fail "al could not receive a single transfer from $eph_drain"

al_post_single=$(enc_balance al)
single_left=$(enc_balance "$eph_drain")
delta_is "$al_pre_single" "$al_post_single" "0" \
    || fail "al is out $(delta_of "$al_pre_single" "$al_post_single") after sending and receiving ${single_amount}qdn"
python3 -c "
from decimal import Decimal
raise SystemExit(0 if Decimal('$single_left') == 0 else 1)
" || fail "$eph_drain holds ${single_left}qdn after a single transfer was received"
echo "sent and received ${single_amount}qdn; wallet empty again"

echo "-------------------------"
echo "9b. five transfers come back in arrival order"
echo "-------------------------"
# Distinct amounts on purpose: identical ones would drain in any order and look correct.
drain_amounts=(1 2 3 4 5)
al_pre=$(enc_balance al)

for amt in $drain_amounts; do
    qadenad_alias tx qadena transfer-funds "$eph_drain" "${amt}qdn" 0qdn \
        --transfer-note "ordered transfer ${amt}" --from al --yes > /dev/null \
        || fail "transfer of ${amt}qdn to $eph_drain failed"
done
echo "sent ${#drain_amounts} transfers: ${drain_amounts} qdn"

# Receive one at a time and check WHICH one arrived, by how much al gained.
for amt in $drain_amounts; do
    before=$(enc_balance al)
    qadenad_alias tx qadena receive-funds "$eph_drain" 0qdn --from al --yes > /dev/null \
        || fail "receive-funds refused while ${amt}qdn was still expected -- a transfer cannot be collected"
    after=$(enc_balance al)
    delta_is "$before" "$after" "$amt" \
        || fail "expected ${amt}qdn next (arrival order) but received $(delta_of "$before" "$after")qdn -- transfers are coming back out of order"
    echo "received ${amt}qdn"
done

remaining=$(enc_balance "$eph_drain")
al_post=$(enc_balance al)
echo "remaining on $eph_drain: $remaining"
echo "al: $al_pre -> $al_post  (delta $(delta_of "$al_pre" "$al_post"))"

# What is left is the wallet's own creation commitment, worth 0 under the current
# create_ephemeral_wallet_incentive.  If that param is ever raised, the expected residual becomes
# that amount rather than 0.
python3 -c "
from decimal import Decimal
raise SystemExit(0 if Decimal('$remaining') == 0 else 1)
" || fail "$eph_drain still holds ${remaining}qdn -- receive-funds left a transfer behind"

delta_is "$al_pre" "$al_post" "0" \
    || fail "al is out $(delta_of "$al_pre" "$al_post") after sending and reclaiming the same amount -- value was lost"
echo "all ${#drain_amounts} transfers came back in order; nothing left behind"

echo "========================="
echo "TRANSFER / RECEIVE TESTS PASSED"
echo "========================="
