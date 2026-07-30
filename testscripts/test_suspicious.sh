#!/bin/zsh
#
# Regression test for suspicious transaction generation.
#
# The enclave scans every transfer (enclave.go, scanTransaction).  Two rules, both keyed on the
# USD value of the transfer -- converted through the pricefeed, so this depends on cn:qdn:usd:
#
#   1. a SINGLE transfer at or above SuspiciousThreshold (x/qadena/common/common.go: "10000usd")
#   2. the AGGREGATE of transfers from one source to one destination reaching that threshold
#
# In both cases the behaviour is the same and is what this script pins down:
#
#   without --opt-in-reason  ->  the transfer is REJECTED outright (ErrGenericScan)
#   with    --opt-in-reason  ->  the transfer succeeds AND a suspicious transaction is recorded,
#                                encrypted to the regulator registered for the jar
#
# That second half is the point: opting in does not suppress the report, it files one.
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

# 1,200,000 qdn = 12,000 usd at cn:qdn:usd 0.01, comfortably over the 10,000 usd threshold
large_amount="1200000"
# what al needs on hand to make the two attempts plus fees
required="3000000"

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
suspicious_count() {
    qadenad_alias query qadena list-suspicious-transaction --output json 2>/dev/null \
        | jq -r '.SuspiciousTransaction | length' 2>/dev/null || echo ""
}

echo "========================="
echo "preflight"
echo "========================="
qadenad_alias status > /dev/null 2>&1 || fail "chain is not reachable -- start it first"
for w in al ann-eph1 treasury; do
    addr_of "$w" > /dev/null 2>&1 || fail "$w not in the keyring -- run testscripts/setup.sh first"
done

# The regulator's private key lives in the enclave params, not the keyring.  The file is a JSON
# blob with a signer id prefixed before the opening brace, so strip everything up to it.
params_file=$(ls "$QADENAHOME"/enclave_config/enclave_params_*.json 2>/dev/null | head -1)
[ -n "$params_file" ] || fail "no enclave params file under $QADENAHOME/enclave_config"
regulator_privk=$(sed 's/^[^{]*//' "$params_file" | jq -r '.SharedEnclaveParams.RegulatorPrivK')
[ -n "$regulator_privk" ] && [ "$regulator_privk" != "null" ] \
    || fail "could not read RegulatorPrivK from $params_file"
regulator_id=$(sed 's/^[^{]*//' "$params_file" | jq -r '.SharedEnclaveParams.RegulatorID')
echo "regulator: $regulator_id"

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
echo "2. a transfer over the threshold WITHOUT --opt-in-reason is refused"
echo "========================="
# --gas auto makes the CLI simulate first, and the scan runs during execution, so ErrGenericScan
# surfaces as a non-zero exit before the tx is broadcast.
if qadenad_alias tx qadena transfer-funds ann-eph1 0qdn "${large_amount}qdn" \
    --transfer-note "over threshold, no opt-in" --from al --yes > /dev/null 2>&1; then
    fail "a ${large_amount}qdn transfer was accepted with no --opt-in-reason"
fi
echo "rejected as expected"

mid_count=$(suspicious_count)
[ "$mid_count" = "$before_count" ] \
    || fail "a refused transfer still filed a suspicious transaction ($before_count -> $mid_count)"
echo "and filed nothing: still $mid_count"

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
decrypted=$(qadenad_alias query qadena list-suspicious-transaction "$regulator_privk" 2>&1)
[ -n "$decrypted" ] || fail "the regulator key decrypted nothing; the report is not readable by $regulator_id"
echo "$decrypted" | tail -20

echo "========================="
echo "5. the funds still queued normally despite being flagged"
echo "========================="
# a flagged transfer is reported, not blocked -- it must still be receivable
qadenad_alias tx qadena receive-funds ann-eph1 0qdn --from ann --yes > /dev/null \
    || fail "ann could not receive the flagged transfer"
echo "ann received the flagged transfer"

echo "========================="
echo "SUSPICIOUS TRANSACTION TESTS PASSED"
echo "========================="
