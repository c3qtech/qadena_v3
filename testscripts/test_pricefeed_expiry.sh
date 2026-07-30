#!/bin/zsh
#
# Regression test for pricefeed EXPIRY: a posted price stops counting once its expiry passes.
#
# Mechanism: SetCurrentPrices filters raw prices by expiry and takes the median of what remains, and
# x/pricefeed EndBlock re-runs it every block.  So an oracle price that expires drops out of the
# median on the next block without anyone doing anything.
#
# This is the precondition for the fail-closed behaviour in the qadena keeper: when a market has NO
# unexpired price, GetCurrentPrice errors, and ConvertFeeToQadena / ScanTransaction now refuse the
# operation instead of substituting a zero rate.  See x/qadena/keeper/exchange_rate.go.
#
# WHY THIS TEST STOPS AT THE MEDIAN AND DOES NOT DRIVE A FEE INTO FAILURE
#
#   Genesis seeds every market with a price expiring 2030-01-01, and raw prices are keyed by
#   (market, oracle) -- the seeded ones carry an EMPTY oracle address, so an oracle posting is a
#   SEPARATE entry and cannot replace or remove them.  There is therefore no way to leave a seeded
#   market with zero unexpired prices before 2030, which means the fee path cannot be pushed into
#   its no-price branch end-to-end on this genesis.
#
#   That is itself worth knowing: the 2030 seeds make an important failure mode untestable, which is
#   the argument for the short expiry config/launch-config.yml recommends.  The no-price branch is
#   covered directly by x/qadena/keeper/exchange_rate_test.go.
#
# Idempotent: the oracle re-posts each run, which REPLACES its previous entry for the market (same
# market+oracle key), and every assertion is against the seeded baseline rather than absolute state.
#
# Run AFTER testscripts/setup_prerequisites.sh (it needs a registered oracle).

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

set -e

function qadenad_alias { "$qadenabin/qadenad" --home "$QADENAHOME" "$@" }

oracle="band-protocol-oracle"
market="cn:eth:usd"
seeded="1916180000000000000000"          # 1916.18, from the genesis postedPriceList
posted="3000000000000000000000"          # 3000.00 -- far from the seed so the median is unmistakable
ttl_seconds=30

fail() {
    echo "FAILED: $1"
    exit 1
}

qdn() { python3 -c "print(int('${1:-0}')/10**18)"; }

price_of() {
    qadenad_alias query pricefeed price "$1" --output json 2>/dev/null \
        | jq -r '.price.price // empty' 2>/dev/null
}

# RFC3339 UTC, N seconds from now -- BSD and GNU date take different flags
future_rfc3339() {
    if date -u -v+"$1"S +%Y-%m-%dT%H:%M:%SZ > /dev/null 2>&1; then
        date -u -v+"$1"S +%Y-%m-%dT%H:%M:%SZ
    else
        date -u -d "+$1 seconds" +%Y-%m-%dT%H:%M:%SZ
    fi
}

echo "========================="
echo "preflight"
echo "========================="
qadenad_alias status > /dev/null 2>&1 || fail "chain is not reachable -- start it first"
qadenad_alias keys show "$oracle" --keyring-backend test > /dev/null 2>&1 \
    || fail "$oracle not in the keyring -- run testscripts/setup_prerequisites.sh first"

n=$(qadenad_alias query pricefeed oracles "$market" --output json 2>/dev/null | jq -r '.oracles | length')
[ "${n:-0}" -gt 0 ] || fail "no oracles registered on $market -- run testscripts/setup_prerequisites.sh first"
echo "chain up, $n oracle(s) on $market"

# The seeded price is the baseline every assertion below is relative to.  If it is not what we think,
# the medians will not match and the failure would be confusing.
before=$(price_of "$market")
echo "$market currently $(qdn "$before")"

echo "========================="
echo "1. post a price that expires in ${ttl_seconds}s"
echo "========================="
expiry=$(future_rfc3339 "$ttl_seconds")
echo "expiry: $expiry"

qadenad_alias tx pricefeed post-price "$market" "$posted" "$expiry" \
    --from "$oracle" --yes --output json \
    --gas-prices $minimum_gas_prices --gas $gas_auto --gas-adjustment $gas_adjustment > /dev/null 2>&1 \
    || fail "post-price failed"
echo "posted $(qdn "$posted")"

echo "========================="
echo "2. while unexpired it counts toward the median"
echo "========================="
# median of the seeded price and the posted one
expected_live=$(python3 -c "print((int('$seeded') + int('$posted')) // 2)")
echo "expecting $(qdn "$expected_live") = median($(qdn "$seeded"), $(qdn "$posted"))"

live=""
for _ in {1..15}; do
    live=$(price_of "$market")
    [ "$live" = "$expected_live" ] && break
    sleep 2
done
echo "$market = $(qdn "$live")"
[ "$live" = "$expected_live" ] \
    || fail "$market is $(qdn "$live"), expected the median $(qdn "$expected_live") while the posted price is live"

echo "========================="
echo "3. once expired it stops counting"
echo "========================="
# EndBlock re-runs SetCurrentPricesForAllMarkets every block, so the median should revert to the
# seeded price alone shortly after the expiry passes -- no further transaction required.
echo "waiting for the posted price to expire..."
reverted=""
for _ in {1..45}; do
    reverted=$(price_of "$market")
    [ "$reverted" = "$seeded" ] && break
    sleep 2
done

echo "$market = $(qdn "$reverted")"
[ "$reverted" = "$seeded" ] \
    || fail "$market is $(qdn "$reverted") after expiry, expected the seeded $(qdn "$seeded") alone"
echo "the expired price dropped out of the median with no further transaction"

echo "========================="
echo "4. the expired entry is still STORED, just not counted"
echo "========================="
# SetPrice never deletes; expiry is applied at aggregation time.  Worth pinning down, because it
# means a market can hold raw prices and still have no usable current price.
raw=$(qadenad_alias query pricefeed raw-prices "$market" --output json 2>/dev/null | jq '.rawPrices | length')
echo "$market raw prices: $raw"
[ "${raw:-0}" -ge 2 ] \
    || fail "expected the expired entry to still be stored alongside the seeded one, found $raw"
echo "expiry filters at aggregation time rather than deleting"

echo "========================="
echo "PRICEFEED EXPIRY TESTS PASSED"
echo "========================="
