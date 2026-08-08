#!/bin/zsh
#
# Regression test for suspicious transaction generation.
#
# The enclave scans every transfer (enclave.go, ScanTransaction).  Two rules, both keyed on the
# USD value of the transfer -- converted through the pricefeed, so this depends on cn:qdn:usd:
#
#   1. a SINGLE transfer at or above the sender's reporting threshold
#   2. the AGGREGATE of transfers from one source to one destination, within a ROLLING WINDOW
#      (suspicious_transaction_window_seconds, 30 days), reaching that threshold
#
# The threshold is per-jurisdiction and is the MOST RESTRICTIVE across the sender's residency and
# citizenship, because both are unconstrained free fields on a credential -- if the loosest won, a
# sender could raise their own limit by editing one.  al is citizenship=US, residency=PH, so the PH
# override (500,000php, about 8,150usd) applies to him rather than the 10,000usd chain default.
# The amounts below clear both, so this script does not depend on which one is selected.
#
# A sender with NO credential cannot transfer at all unless allow_transfer_without_ekyc is set: no
# residency and no citizenship means no jurisdiction, hence no threshold to be held to.  Case 10
# covers that.  Note the funding here goes through `tx bank send`, which is NOT scanned at all --
# an escape hatch this script cannot close and does not pretend to.
#
# NOT covered here: window EXPIRY.  30 days cannot elapse inside a test run, and shrinking the
# window would need a governance change that would then apply to every later suite.  Pruning and
# aggregation are unit-tested instead -- x/qadena/common/suspicious_policy_test.go.
#
# In both cases the behaviour is the same and is what this script pins down:
#
#   without --opt-in-reason  ->  the transfer succeeds AND a report is filed carrying the default
#                                reason, "No reason provided"
#   with    --opt-in-reason  ->  the transfer succeeds AND a report is filed carrying that reason,
#                                encrypted to the regulator registered for the jar
#
# Opting in does not suppress the report, it only supplies the reason text.  Refusal is no longer
# the no-reason behaviour: block_transfer_without_opt_in_reason (param 26, default false) restores
# it per chain, and is unit-tested in x/qadena/common/suspicious_policy_test.go rather than here,
# since flipping it mid-suite would need a governance proposal.
#
# The earlier contract -- refuse when no reason is given -- filed nothing in exactly the case worth
# reporting, which is why it changed.
#
# At cn:qdn:usd = 0.01 the threshold is 1,000,000 qdn, so the amounts here are large.  al is topped
# up from the treasury when short, which is what makes the script re-runnable.
#
# Run AFTER testscripts/setup.sh.

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

set -e

function qadenad_alias { "$qadenabin/qadenad" --home "$QADENAHOME" "$@" }

# 1,200,000 qdn = 12,000 usd at cn:qdn:usd 0.01, comfortably over either threshold
large_amount="1200000"

# For the AGGREGATE rule: three transfers that are individually well under the limit but together
# clear it.  The amounts are chosen to land on the same side of the threshold whichever one applies,
# so the test does not silently depend on al's PH override still being configured:
#
#                            usd     vs PH 8,148   vs default 10,000
#   one transfer           3,500        under            under
#   after two              7,000        under            under
#   after three           10,500         OVER             OVER
#
# The third is the one that must trip, and only because of what came before it.
aggregate_amount="350000"
# small enough to be invisible to either rule; used to prove a reported pair has been RESET
tiny_amount="10000"

# what al needs on hand for the two single-transfer attempts, the aggregate run, and fees
required="5000000"

fail() {
    echo "FAILED: $1"
    exit 1
}

addr_of() {
    qadenad_alias keys show "$1" -a --keyring-backend test 2>/dev/null
}

# transparent (bank) balance in whole qdn, as an integer string
bank_qdn() {
    local amt
    amt=$(qadenad_alias query bank balances "$1" --output json 2>/dev/null \
        | jq -r '.balances[] | select(.denom=="aqdn") | .amount' 2>/dev/null) || amt=""
    [ -n "$amt" ] || { echo 0; return; }
    python3 -c "print(int('$amt') // 10**18)"
}

# Counting must use the KEYLESS form.  Passing the regulator key switches the CLI into a decrypted
# human-readable print that emits no JSON at all -- with zero records it prints nothing, which is
# indistinguishable from a failed query.  Keyless returns the raw proto response, which is countable.
# The decrypting form is still used below, to show that the record is readable by the regulator.
#
# COUNT WITH --count-total, NOT by measuring the returned array.  --limit defaults to 100, so
# `.SuspiciousTransaction | length` stops at 100 no matter how many records exist and every
# "did this file a report?" assertion below silently becomes `100 -gt 100`, which is false forever.
#
# Nothing detected it for a long time because it needs a hundred reports on one chain to appear, and
# until the suite was run repeatedly no chain ever had that many.  It surfaced on a loop of it: runs
# 1 and 2 green, then every run from 7 on failing in suspicious, bank-scan and evm at once, all of
# them reporting a threshold that had stopped being applied.  The chain was fine -- it had 281
# records and was still filing them.
suspicious_count() {
    qadenad_alias query qadena list-suspicious-transaction --count-total --output json 2>/dev/null \
        | jq -r '.pagination.total' 2>/dev/null || echo ""
}

echo "========================="
echo "preflight"
echo "========================="
qadenad_alias status > /dev/null 2>&1 || fail "chain is not reachable -- start it first"
for w in al ann ann-eph1 victor victor-eph1 treasury; do
    addr_of "$w" > /dev/null 2>&1 || fail "$w not in the keyring -- run testscripts/setup.sh first"
done

# The regulator's private key lives in the enclave params, not the keyring.  The file is a JSON
# blob with a signer id prefixed before the opening brace, so strip everything up to it.
#
# THAT ONLY WORKS IN DEBUG MODE, and the difference is the point rather than an inconvenience.  The
# debug enclave "seals" by prefixing an id onto plaintext JSON, so the regulator private key is
# sitting in a file readable by anyone on the box.  A real SGX enclave seals with the hardware key,
# so the same file is ciphertext and the key CANNOT be recovered from outside the enclave by anyone,
# including root and including this test.  That is the security property the whole design rests on.
#
# So under real sealing this suite drops the assertions that need the key and keeps the rest, and it
# says exactly which ones it dropped.  Failing instead would report a broken chain when the chain is
# behaving correctly; skipping quietly would let "suspicious PASSED" imply a decryption check that
# never ran.
params_file=$(ls "$QADENAHOME"/enclave_config/enclave_params_*.json 2>/dev/null | head -1)
[ -n "$params_file" ] || fail "no enclave params file under $QADENAHOME/enclave_config"

sealed_plaintext=0
if sed 's/^[^{]*//' "$params_file" 2>/dev/null | jq -e '.SharedEnclaveParams' > /dev/null 2>&1; then
    sealed_plaintext=1
fi

regulator_privk=""
if [ $sealed_plaintext -eq 1 ]; then
    regulator_privk=$(sed 's/^[^{]*//' "$params_file" | jq -r '.SharedEnclaveParams.RegulatorPrivK')
    [ -n "$regulator_privk" ] && [ "$regulator_privk" != "null" ] \
        || fail "could not read RegulatorPrivK from $params_file"
    regulator_id=$(sed 's/^[^{]*//' "$params_file" | jq -r '.SharedEnclaveParams.RegulatorID')
    echo "regulator: $regulator_id"
else
    # Distinguished from a corrupt file by checking the enclave is genuinely a real one; otherwise a
    # debug params file that had been truncated would silently take this branch and disable the
    # decryption assertion on a chain where it should have worked.
    use_real_enclave "$qadenabin/qadenad_enclave" \
        || fail "$params_file is not parseable and the enclave is NOT a real SGX one, so it should have been plaintext -- the file looks corrupt"
    echo "REAL SGX SEALING: $params_file is ciphertext, so the regulator key cannot be read from outside the enclave."
    echo "NOT VERIFIED IN THIS RUN: that a filed report decrypts with the regulator key (needs that key)."
    echo "STILL VERIFIED: that crossing the threshold FILES a report, that opt-in is respected, and the counts."
fi

# the threshold is evaluated in USD, so a missing price makes this test meaningless
qdn_usd=$(qadenad_alias query pricefeed price cn:qdn:usd --output json 2>/dev/null | jq -r '.price.price')
[ -n "$qdn_usd" ] && [ "$qdn_usd" != "null" ] \
    || fail "cn:qdn:usd has no price -- the suspicious threshold is evaluated in USD and cannot be reached"
echo "cn:qdn:usd = $(python3 -c "print(int('$qdn_usd')/10**18)")"
echo "transferring ${large_amount}qdn = $(python3 -c "print(${large_amount}*int('$qdn_usd')/10**18)") usd against a 10000usd threshold"

before_count=$(suspicious_count)
[ -n "$before_count" ] || fail "could not list suspicious transactions with the regulator key"
echo "suspicious transactions on record: $before_count"

echo "========================="
echo "1. top up al if short (idempotent)"
echo "========================="
al_addr=$(addr_of al)
have=$(bank_qdn "$al_addr")
echo "al transparent balance: ${have}qdn"
if [ "$have" -lt "$required" ]; then
    echo "funding al with ${required}qdn from treasury"
    result=$(qadenad_alias tx bank send treasury "$al_addr" "${required}qdn" \
        --from treasury --yes --output json \
        --gas-prices $minimum_gas_prices --gas auto --gas-adjustment $gas_adjustment) \
        || fail "could not fund al from treasury"
    tx_hash=$(echo "$result" | jq -r .txhash)
    qadenad_alias query wait-tx "$tx_hash" --timeout 30s > /dev/null || fail "funding tx did not land"
    have=$(bank_qdn "$al_addr")
    echo "al transparent balance now: ${have}qdn"
    [ "$have" -ge "$large_amount" ] || fail "al still short after funding: ${have}qdn"
else
    echo "already funded, skipping"
fi

echo "========================="
echo "2. a transfer over the threshold WITHOUT --opt-in-reason is REPORTED, not refused"
echo "========================="
# THIS ASSERTION WAS INVERTED, and deliberately so.
#
# It used to require refusal, which is what the chain did when a reason was mandatory.  A missing
# reason then meant the transfer was blocked and the regulator was told NOTHING -- the transaction
# most worth reporting produced the least evidence.  block_transfer_without_opt_in_reason (param 26,
# default false) changed that: the transfer proceeds and a report is filed carrying the default
# reason, so refusing is now opt-in per chain rather than the only behaviour.
#
# Setting the param to true restores refusal on both this path and the bank path; that branch is
# covered by unit tests in x/qadena/common/suspicious_policy_test.go rather than here, because
# flipping a chain param mid-suite would need a governance proposal and would leave the rest of the
# run measuring a different chain.
# RE-BASELINE HERE, not at preflight.  Case 1 tops al up with 5,000,000qdn from the treasury, which
# is itself a $50,000 bank send and now files its OWN report -- it did not before, because the
# treasury was exempt from scanning.  Measuring from the preflight count would let that top-up
# satisfy the assertion below, so this case would pass even if the transfer reported nothing.
before_count=$(suspicious_count)
[ -n "$before_count" ] || fail "could not re-read the suspicious transaction count"
echo "baseline after the top-up: $before_count"

qadenad_alias tx qadena transfer-funds ann-eph1 0qdn "${large_amount}qdn" \
    --transfer-note "over threshold, no opt-in" --from al --yes > /dev/null 2>&1 \
    || fail "a ${large_amount}qdn transfer with no --opt-in-reason should be reported and allowed, not refused"
echo "accepted as expected"

# ... and it filed a report.  Without this the case above would pass just as well if the threshold
# had stopped being applied at all, which is the failure mode that matters most here.
mid_count=""
i=0
while [ $i -lt 15 ]; do
    mid_count=$(suspicious_count)
    [ "$mid_count" -gt "$before_count" ] 2>/dev/null && break
    sleep 2
    i=$((i + 1))
done
[ "$mid_count" -gt "$before_count" ] 2>/dev/null \
    || fail "an over-threshold transfer with no reason filed NO report ($before_count -> $mid_count)"
echo "and filed a report: $before_count -> $mid_count"
before_count="$mid_count"

echo "========================="
echo "3. the same transfer WITH --opt-in-reason succeeds"
echo "========================="
qadenad_alias tx qadena transfer-funds ann-eph1 0qdn "${large_amount}qdn" \
    --opt-in-reason "regression test: large transfer" \
    --transfer-note "over threshold, opted in" --from al --yes > /dev/null \
    || fail "transfer with --opt-in-reason was refused"
echo "accepted"

echo "========================="
echo "4. ... and files a suspicious transaction with the regulator"
echo "========================="
# the enclave records it during EndBlock, so give it a couple of blocks
after_count=""
for _ in {1..15}; do
    after_count=$(suspicious_count)
    [ "$after_count" != "$mid_count" ] && break
    sleep 2
done

echo "suspicious transactions: $mid_count -> $after_count"
[ "$after_count" != "$mid_count" ] \
    || fail "the opted-in transfer was accepted but no suspicious transaction was filed"

echo "-------------------------"
echo "the report must be readable BY THE REGULATOR -- it is encrypted to their key"
echo "-------------------------"
if [ $sealed_plaintext -eq 1 ]; then
    decrypted=$(qadenad_alias query qadena list-suspicious-transaction "$regulator_privk" 2>&1)
    [ -n "$decrypted" ] || fail "the regulator key decrypted nothing; the report is not readable by $regulator_id"
    echo "$decrypted" | tail -20
else
    # Under real sealing the key is unavailable to this script by design, so the strongest thing that
    # can still be shown from outside is that the report EXISTS and is not stored in the clear.  That
    # is worth asserting rather than passing over: a report that listed readably without a key would
    # mean the encryption had stopped being applied, which is the failure that matters most here and
    # is detectable without ever holding the key.
    echo "REAL SGX SEALING: the regulator key is inside the enclave, so decryption cannot be checked here."
    clear_listing=$(qadenad_alias query qadena list-suspicious-transaction --output json 2>/dev/null)
    echo "$clear_listing" | grep -qiE '"(srcWalletID|dstWalletID|amount)"[[:space:]]*:[[:space:]]*"[a-z]+1[a-z0-9]{20,}"' \
        && fail "a suspicious transaction lists readable wallet ids WITHOUT the regulator key; the report is not encrypted"
    echo "reports are present and not readable without the regulator key"
fi

echo "========================="
echo "5. the funds still queued normally despite being flagged"
echo "========================="
# a flagged transfer is reported, not blocked -- it must still be receivable
qadenad_alias tx qadena receive-funds ann-eph1 0qdn --from ann --yes > /dev/null \
    || fail "ann could not receive the flagged transfer"
echo "ann received the flagged transfer"

# NOW DRAIN THE REST OF ann-eph1's QUEUE, or this suite strands funds that the NEXT run reads as
# its own.  This is what made the suite non-repeatable.
#
# Cases 2 and 3 each queue an entry of $large_amount; receive-funds takes exactly ONE queued entry
# per call, so the single receive above leaves the other one behind.  It survives to the next run,
# where test_transfers.sh queues 100qdn into the same wallet, drains the queue, and measures the
# delta:
#
#     ann-eph1: 1200100.000000000000000000 -> 100.000000000000000000
#     FAILED: ann-eph1 released -1200000.000000000000000000, expected -100
#
# which reads as a transfer bug and is nothing of the kind -- test_transfers.sh reads the queue it
# is handed, and this suite handed it a stale entry.  Only the FIRST run after genesis passes.
#
# The aggregate cases below already avoid exactly this by sending to victor-eph1 and draining it in
# a loop; ann-eph1 could not be redirected the same way, because case 5 has to prove that ANN
# receives the flagged transfer.  So it gets the same tidy-up instead, and is best-effort for the
# same reason: nothing after this point asserts on what is left here.
for _ in {1..6}; do
    qadenad_alias tx qadena receive-funds ann-eph1 0qdn --from ann --yes > /dev/null 2>&1 || break
done
echo "ann-eph1 queue drained, so the next run starts from an empty queue"

echo "========================="
echo "6. sub-threshold transfers accumulate without firing"
echo "========================="
# The aggregate rule, which nothing above reaches: cases 2-5 all trip the SINGLE-transfer rule, and
# that check returns before the transfer is recorded, so they never enter the window at all.
#
# The destination is victor-eph1, NOT one of ann's, and that matters.  An ephemeral wallet holds a
# queue with one entry per incoming transfer, and test_transfers.sh reads only the FIRST entry when
# it measures a delta -- correct only while a queue holds a single transfer.  These cases queue
# several, so pointing them at ann-eph1 or ann-eph2 would leave that suite reading a stale entry and
# failing on a later run.  Nothing asserts on victor-eph1's balance.
#
# Each transfer here is far below the limit, so any firing before the third would mean the
# single-transfer rule is reading the wrong amount.
count_before_agg=$(suspicious_count)
for i in 1 2; do
    qadenad_alias tx qadena transfer-funds victor-eph1 0qdn "${aggregate_amount}qdn" \
        --transfer-note "regression test: aggregate leg $i" --from al --yes > /dev/null \
        || fail "sub-threshold transfer $i was refused; it is well under the limit on its own"
done
echo "two transfers of ${aggregate_amount}qdn accepted"

count_after_two=$(suspicious_count)
[ "$count_after_two" = "$count_before_agg" ] \
    || fail "the aggregate fired early ($count_before_agg -> $count_after_two); two legs are still under the limit"
echo "nothing filed yet: still $count_after_two"

echo "========================="
echo "7. the transfer that crosses the aggregate is REPORTED without --opt-in-reason"
echo "========================="
# The rule-2 path, inverted for the same reason as case 2: with
# block_transfer_without_opt_in_reason false, crossing the aggregate reports rather than refuses.
#
# The amount is identical to the two that just succeeded and neither of those reported anything, so
# the only thing that can make this one report is what came before it -- which is exactly the
# rolling window doing its job.  That is what makes this a test of the window rather than of the
# single-transfer rule.
qadenad_alias tx qadena transfer-funds victor-eph1 0qdn "${aggregate_amount}qdn" \
    --transfer-note "crosses aggregate, no opt-in" --from al --yes > /dev/null 2>&1 \
    || fail "the transfer crossing the aggregate threshold should be reported and allowed, not refused"
echo "accepted as expected"

count_after_agg_noreason=""
i=0
while [ $i -lt 15 ]; do
    count_after_agg_noreason=$(suspicious_count)
    [ "$count_after_agg_noreason" -gt "$count_after_two" ] 2>/dev/null && break
    sleep 2
    i=$((i + 1))
done
[ "$count_after_agg_noreason" -gt "$count_after_two" ] 2>/dev/null \
    || fail "crossing the aggregate threshold filed NO report ($count_after_two -> $count_after_agg_noreason)"
echo "and filed an aggregate report: $count_after_two -> $count_after_agg_noreason"

echo "========================="
echo "8. the aggregate rule again, this time WITH --opt-in-reason"
echo "========================="
# THE WINDOW HAS TO BE REBUILT FIRST, and that is the whole reason this case looks the way it does.
#
# It used to send a single transfer here, because case 7 REFUSED its transfer and a refusal leaves
# the window untouched -- so the accumulated total was still sitting there, one transfer short of
# crossing.  Case 7 now REPORTS instead, and a report drops that destination's entries, so the
# window is empty at this point and a lone transfer cannot cross anything.  Sending one and
# expecting a report would be testing nothing at all.
#
# So: two sub-threshold transfers to re-accumulate, then a third carrying the reason.
for i in 1 2; do
    qadenad_alias tx qadena transfer-funds victor-eph1 0qdn "${aggregate_amount}qdn" \
        --transfer-note "rebuilding the window $i" --from al --yes > /dev/null \
        || fail "sub-threshold transfer $i (rebuilding the window) was refused"
done

count_rebuilt=$(suspicious_count)
[ "$count_rebuilt" = "$count_after_agg_noreason" ] \
    || fail "rebuilding the window filed a report early ($count_after_agg_noreason -> $count_rebuilt); the reset in case 7 did not clear it"

qadenad_alias tx qadena transfer-funds victor-eph1 0qdn "${aggregate_amount}qdn" \
    --opt-in-reason "regression test: aggregate total" \
    --transfer-note "crosses aggregate, opted in" --from al --yes > /dev/null \
    || fail "the opted-in aggregate transfer was refused"

count_after_agg=""
for _ in {1..15}; do
    count_after_agg=$(suspicious_count)
    [ "$count_after_agg" != "$count_rebuilt" ] && break
    sleep 2
done
echo "suspicious transactions: $count_rebuilt -> $count_after_agg"
[ "$count_after_agg" != "$count_rebuilt" ] \
    || fail "three transfers totalling over the threshold filed no aggregate report"

echo "========================="
echo "9. a reported pair is RESET, not left primed"
echo "========================="
# After firing, the enclave drops that destination's entries.  Without it every later transfer to
# the same destination would re-report the same accumulated total forever.  A tiny transfer must
# therefore file nothing -- if the window had been left intact, it would still be over the limit and
# would report again immediately.
qadenad_alias tx qadena transfer-funds victor-eph1 0qdn "${tiny_amount}qdn" \
    --transfer-note "regression test: after reset" --from al --yes > /dev/null \
    || fail "a tiny transfer after the aggregate fired was refused; the pair was not reset"

sleep 6
count_after_reset=$(suspicious_count)
[ "$count_after_reset" = "$count_after_agg" ] \
    || fail "a tiny transfer re-reported ($count_after_agg -> $count_after_reset); the pair was not reset after firing"
echo "no further report filed: still $count_after_reset"

# Best-effort tidy-up.  receive-funds drains exactly ONE queued entry per call and an eph wallet
# holds one entry per incoming transfer, so draining fully needs a loop -- and it is deliberately
# allowed to fail: nothing in this script or any other asserts on victor-eph1's balance, so a
# leftover entry is untidy rather than wrong.  What DOES have to be repeatable is the window, and
# that is reset by the report in case 8 regardless of whether the funds are collected.
for _ in {1..6}; do
    qadenad_alias tx qadena receive-funds victor-eph1 0qdn --from victor --yes > /dev/null 2>&1 || break
done

echo "========================="
echo "10. a wallet with no eKYC data may not send at all"
echo "========================="
# The threshold is chosen from the sender's residency and citizenship, so a sender with neither has
# no limit to be measured against.  Falling back to the chain default would make "hold no
# credential" the cheapest way to pick your own threshold, so the transfer is refused instead --
# governed by allow_transfer_without_ekyc, which is false here and in launch-config.yml.
#
# The wallet below is built exactly as a real user is (real wallet, then linked eph wallet) and is
# funded by the create-wallet incentive; the ONLY thing it lacks is a claimed credential.  Asserting
# the specific code matters: a bare "it failed" would also pass if the wallet simply could not
# transfer for want of funds or an eph wallet, which would test nothing.
noekyc_wallet="noekyc-$(date +%s | tail -c 7)"
expect_ok_tx() {
    "$@" > /dev/null 2>&1 || fail "setup step failed: $*"
}
expect_ok_tx qadenad_alias tx qadena create-wallet "$noekyc_wallet" pioneer1 create-wallet-sponsor --yes
expect_ok_tx qadenad_alias tx qadena create-wallet "$noekyc_wallet-eph1" pioneer1 create-wallet-sponsor \
    --link-to-real-wallet "$noekyc_wallet" --eph-account-index 1 --yes
echo "created $noekyc_wallet with an eph wallet and no credential"

# Must sit inside the create_wallet_incentive (500qdn encrypted) this wallet was funded with.  Ask
# for more and the transfer fails on funds BEFORE the scan runs -- which is why the code is asserted
# below rather than the mere fact of failure.
noekyc_amount="100"
noekyc_out=$(qadenad_alias tx qadena transfer-funds ann-eph1 0qdn "${noekyc_amount}qdn" \
    --transfer-note "no ekyc" --from "$noekyc_wallet" --yes 2>&1) && noekyc_rc=0 || noekyc_rc=$?
if [ "$noekyc_rc" -eq 0 ]; then
    fail "a wallet with no credential was allowed to transfer"
fi
if ! echo "$noekyc_out" | grep -q "code 1158"; then
    echo "$noekyc_out" | grep -oE "codespace qadena code [0-9]+: [A-Za-z ;]+" | tail -1
    fail "expected qadena code 1158 (no eKYC), got the above -- the transfer must be refused for the RIGHT reason"
fi
echo "rejected as expected (qadena code 1158)"

echo "========================="
echo "SUSPICIOUS TRANSACTION TESTS PASSED"
echo "========================="
