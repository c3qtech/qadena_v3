#!/bin/zsh
#
# End-to-end test of the pricefeed: that a registered oracle can post a price, that the posted price
# reaches the market's current price, and -- the part that used to be broken -- that it reaches ONLY
# that market.
#
# Background: IterateRawPricesByMarket took a marketId and then iterated the whole PostedPrice
# keyspace with an empty prefix, so GetRawPrices returned every market's prices and SetCurrentPrices
# stored the median across all of them as each individual market's price.  Every market ended up
# with the same number -- cn:btc:usd read ~0.65 instead of its actual price.  The fix restricts the
# iterator to the "<marketId>/" key prefix.  This script proves that on live data.
#
# Run AFTER testscripts/setup_prerequisites.sh, which registers the oracles.  Safe to re-run.

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

# set -e after the source: setup_env.sh queries the chain for gas prices and falls back on failure
set -e

function qadenad_alias { "$qadenabin/qadenad" --home "$QADENAHOME" "$@" }

# the oracle that posts, and the market it posts to.  cn:eth:usd is deliberately NOT the market the
# credential fees convert through (cn:qdn:php), so this test cannot perturb fee amounts.
oracle="band-protocol-oracle"
# ENV-DEFAULTED.  The requirement is a market that credential fees do NOT convert through
# (cn:qdn:php) -- not these specific two.  The devnet ships six markets and eth/btc are the
# obvious spare pair; a launch chain ships three, so it must name its own or the suite fails
# with "no oracles registered on cn:eth:usd" against a perfectly healthy chain.
target_market="${QADENA_PF_TARGET:-cn:eth:usd}"
control_market="${QADENA_PF_CONTROL:-cn:btc:usd}"

# genesis seeds cn:eth:usd at 1916.18 and cn:btc:usd at 64363.66
#
# LegacyDec is carried on the wire as an integer scaled by 10^18, and autocli hands the argument
# straight to its unmarshaller -- so "2000.00" is rejected with "cannot unmarshal into a *big.Int".
# Post the scaled form.  Queries return the same representation.
#
# Two candidate prices, because this script has to be re-runnable: raw prices are keyed by
# (market, oracle), so re-posting the SAME value from the same oracle replaces it with an identical
# value and the current price never moves -- which would look like a failure.  Pick whichever
# candidate is not already in effect, so every run produces a real change.
# The seeded price a market MUST report, read from THIS chain's genesis rather than hardcoded.
# The devnet seeds cn:eth:usd at 1916.18 and cn:btc:usd at 64363.66; a launch chain seeds other
# markets at other prices, and a stale constant here fails a perfectly healthy chain while
# claiming "prices are being blended across markets" -- pointing the reader at the iterator bug
# this suite exists to detect, which is not what went wrong.
genesis_price_of() {
    local p
    p=$(jq -r --arg m "$1" \
        '.app_state.pricefeed.postedPriceList[]? | select(.marketId==$m) | .price' \
        "$QADENAHOME/config/genesis.json" 2>/dev/null | head -1)
    [ -n "$p" ] || return 1
    python3 -c "from decimal import Decimal; print(int(Decimal('$p') * 10**18))"
}

price_a="2000000000000000000000"        # 2000.00 -> median with the seed = 1958.09
price_b="2100000000000000000000"        # 2100.00 -> median with the seed = 2008.09
expiry="2035-01-01T00:00:00Z"

# the current price is the median of the seeded price and whatever the oracle last posted
median_with_seed() {
    python3 -c "print((int('$seeded_target') + int('$1')) // 2)"
}

# 10^18-scaled integer -> human decimal, for legible output
human() {
    [ -n "$1" ] || { echo ""; return; }
    python3 -c "print(int('$1')/10**18)" 2>/dev/null || echo "$1"
}

fail() {
    echo "FAILED: $1"
    exit 1
}

price_of() {
    local p
    p=$(qadenad_alias query pricefeed price "$1" --output json 2>/dev/null \
        | jq -r '.price.price // empty' 2>/dev/null) || p=""
    echo "$p"
}

seeded_target=$(genesis_price_of "$target_market") \
    || fail "$target_market is not in the genesis postedPriceList -- set QADENA_PF_TARGET to a market this chain actually seeds"
seeded_control=$(genesis_price_of "$control_market") \
    || fail "$control_market is not in the genesis postedPriceList -- set QADENA_PF_CONTROL to a market this chain actually seeds"

echo "========================="
echo "preflight"
echo "========================="
qadenad_alias status > /dev/null 2>&1 || fail "chain is not reachable -- start it first"
qadenad_alias keys show "$oracle" --keyring-backend test > /dev/null 2>&1 \
    || fail "$oracle not in the keyring -- run testscripts/setup_prerequisites.sh first"

oracles_on_target=$(qadenad_alias query pricefeed oracles "$target_market" --output json 2>/dev/null | jq -r '.oracles | length')
[ "${oracles_on_target:-0}" != "0" ] \
    || fail "no oracles registered on $target_market -- run testscripts/setup_prerequisites.sh first"
echo "chain up, $oracle present, $oracles_on_target oracle(s) on $target_market"

echo "========================="
echo "1. per-market isolation (the iterator fix)"
echo "========================="
# Each market must report its OWN seeded price.  Before the fix every market reported the median
# across all six, which for the genesis set was ~0.654805.
target_before=$(price_of "$target_market")
control_before=$(price_of "$control_market")
echo "$target_market  = $(human "$target_before")"
echo "$control_market = $(human "$control_before")"

[ -n "$target_before" ] || fail "$target_market has no current price -- did the seeded postedPriceList load?"
[ -n "$control_before" ] || fail "$control_market has no current price"

# the decisive assertion: two markets whose seeded prices differ by four orders of magnitude must
# not report the same number
[ "$target_before" != "$control_before" ] \
    || fail "every market reports the same price ($(human "$target_before")) -- IterateRawPricesByMarket is still unfiltered"

# Pre-fix this market reported the cross-market median instead of its own seeded price.
[ "$control_before" = "$seeded_control" ] \
    || fail "$control_market = $(human "$control_before"), expected its seeded $(human "$seeded_control") -- prices are being blended across markets"
echo "$control_market reads its own seeded price, not a cross-market median"

# and exactly one raw price per market is the direct signature of the fixed iterator
raw_n=$(qadenad_alias query pricefeed raw-prices "$control_market" --output json 2>/dev/null | jq '.rawPrices | length')
[ "$raw_n" = "1" ] \
    || fail "$control_market has $raw_n raw prices, expected 1 -- GetRawPrices is returning other markets' prices"
echo "$control_market has exactly 1 raw price"

echo "========================="
echo "2. a registered oracle can post"
echo "========================="
# pick the candidate that is not already in effect, so the price genuinely moves on every run
if [ "$target_before" = "$(median_with_seed "$price_a")" ]; then
    posted_price="$price_b"
else
    posted_price="$price_a"
fi
expected_after=$(median_with_seed "$posted_price")
echo "posting $(human "$posted_price"); expecting the median with the seed to become $(human "$expected_after")"

result=$(qadenad_alias tx pricefeed post-price "$target_market" "$posted_price" "$expiry" \
    --from "$oracle" --yes --output json \
    --gas-prices $minimum_gas_prices --gas auto --gas-adjustment $gas_adjustment) \
    || fail "post-price from $oracle failed"
[ "$(echo "$result" | jq -r .code)" = "0" ] \
    || fail "post-price tx failed: $(echo "$result" | jq -r .raw_log)"

tx_hash=$(echo "$result" | jq -r .txhash)
# confirm_tx, NOT a bare `query wait-tx`.  wait-tx SUBSCRIBES to a websocket event for the hash,
# so when the transaction is included BEFORE the subscription is established the event never
# arrives and it reports a timeout for a transaction that SUCCEEDED.  At ~1.5s blocks that race is
# routinely lost: observed in regression run 11, where this call failed while the tx sat committed
# at height 35977 with code 0.  confirm_tx polls `query tx` regardless of how the wait turned out,
# which is the whole reason it exists.
confirm_tx "$tx_hash" 30 || fail "post-price tx $tx_hash did not land"
echo "posted $(human "$posted_price") to $target_market"

echo "========================="
echo "3. the posted price reaches the current price"
echo "========================="
# current prices are recomputed on a block boundary, so give it a couple of blocks
target_after=""
for _ in {1..15}; do
    target_after=$(price_of "$target_market")
    [ "$target_after" = "$expected_after" ] && break
    sleep 2
done

echo "$target_market: $(human "$target_before") -> $(human "$target_after")"
# asserting the exact median, not merely "it changed", so this also checks the aggregation
[ "$target_after" = "$expected_after" ] \
    || fail "$target_market is $(human "$target_after"), expected the median $(human "$expected_after")"

# two raw prices now (the genesis seed plus this post), and the current price is their median
raw_n=$(qadenad_alias query pricefeed raw-prices "$target_market" --output json 2>/dev/null | jq '.rawPrices | length')
echo "$target_market now has $raw_n raw prices"

echo "========================="
echo "4. the post did NOT leak into other markets"
echo "========================="
# this is the regression the iterator fix exists for: posting to eth must not move btc
control_after=$(price_of "$control_market")
echo "$control_market: $(human "$control_before") -> $(human "$control_after")"
[ "$control_after" = "$control_before" ] \
    || fail "posting to $target_market changed $control_market ($(human "$control_before") -> $(human "$control_after")) -- prices are leaking across markets"

echo "========================="
echo "5. an unregistered account may NOT post"
echo "========================="
# treasury is not in any market's oracle list, so GetOracle must reject it.
#
# The exit code is a sound verdict here: --gas auto makes the CLI simulate first, and simulation
# executes the message, so "oracle does not exist or not authorized" surfaces as a non-zero exit
# before the tx is ever broadcast.
raw_before=$(qadenad_alias query pricefeed raw-prices "$target_market" --output json 2>/dev/null | jq '.rawPrices | length')

if qadenad_alias tx pricefeed post-price "$target_market" "1234000000000000000000" "$expiry" \
    --from treasury --yes --output json \
    --gas-prices $minimum_gas_prices --gas auto --gas-adjustment $gas_adjustment > /dev/null 2>&1; then
    fail "treasury is not a registered oracle but its post-price succeeded"
fi
echo "rejected as expected"

# and prove it by state, not just by the exit code
raw_after=$(qadenad_alias query pricefeed raw-prices "$target_market" --output json 2>/dev/null | jq '.rawPrices | length')
[ "$raw_after" = "$raw_before" ] \
    || fail "$target_market raw price count went $raw_before -> $raw_after; the unregistered post was recorded"
echo "$target_market still has $raw_after raw prices"

echo "========================="
echo "PRICEFEED TESTS PASSED"
echo "========================="
