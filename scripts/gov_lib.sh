#!/bin/zsh
#
# Shared helpers for the operator governance scripts.  Source, do not execute.
#
# WHY THESE EXIST.  Governance is required for exactly one routine operation -- registering an
# enclave measurement -- and until now the only thing that submitted a proposal was a TEST FIXTURE
# (testscripts/test_update_enclave_identity.sh).  It hardcodes the message, votes only from
# pioneer1, and asserts nothing about the outcome, so on a balanced fleet where pioneer1 holds 25%
# it cheerfully reports success while the proposal expires below the 33.4% quorum.  That is not a
# hypothetical: it happened twice on 2026-08-21 and cost an hour each time, because every symptom
# points at the enclave rather than at the vote.
#
# The failure mode governs the design: a proposal that cannot reach quorum does not ERROR, it TIMES
# OUT.  So these scripts check reachability BEFORE submitting, and poll to a terminal state after.

# qadenad, addressed directly.  NOT the qadenad_alias from setup_env.sh: that is a zsh alias, and
# aliases are resolved at PARSE time, so it is undefined inside any function or `zsh -c` string that
# was parsed before setup_env.sh was sourced.  That silently produced "command not found" inside
# scripts that had sourced it successfully.
qq() { "$qadenabin/qadenad" --home "$QADENAHOME" "$@" }

gov_param() { qq q gov params -o json 2>/dev/null | jq -r "$1" }

# total bonded stake, and the stake a given account can actually swing.
#
# Voting power follows the DELEGATOR, not the validator, so "can these accounts reach quorum" is a
# question about delegations -- which is why a pioneer that operates a validator may still control
# very little of it.
# STAKE IS SUMMED AS TEXT THROUGH bc, NEVER THROUGH jq's tonumber.
#
# tonumber turns 10100050000000000000000000 into an IEEE double and prints it back as
# 1.0100050000000001e+25 -- which bc cannot parse, so every percentage came out 0.00% next to a
# "(standard_in) 1: syntax error" that is easy to skim past.  A wrong number that looks like a real
# number is the worst outcome here, because the whole point of these helpers is to tell you whether
# a vote can reach quorum.
sum_lines() {
    local t
    t=$(cat)
    [ -z "$t" ] && { echo 0; return }
    echo "$t" | paste -sd+ - | bc
}

bonded_total() {
    qq q staking validators -o json 2>/dev/null \
      | jq -r '.validators[] | select(.status=="BOND_STATUS_BONDED") | .tokens' 2>/dev/null \
      | sum_lines
}

voter_power() {
    qq q staking delegations "$1" -o json 2>/dev/null \
      | jq -r '.delegation_responses[]?.balance.amount' 2>/dev/null \
      | sum_lines
}

# pct <part> <whole> -- percentage as a plain decimal string, "0" if the inputs are unusable.
pct() {
    [ -z "$1" ] || [ -z "$2" ] || [ "$2" = "0" ] && { echo 0; return }
    echo "scale=4; $1 * 100 / $2" | bc 2>/dev/null || echo 0
}

addr_of() { qq keys show "$1" -a 2>/dev/null }

# Report whether the named accounts can clear quorum, WITHOUT submitting anything.
# Returns 0 if they can, 1 if they cannot.
# ALL ARITHMETIC GOES THROUGH bc.  Stake here is ~1e25 aqdn and zsh's $(( )) is 64-bit: it reports
# "number truncated after 20 digits" and yields garbage, which first showed up as every voter having
# 0.00% of bonded stake -- a number that looks like a real answer.
gov_can_reach_quorum() {
    local total quorum sum=0 p a name share combined qpct
    total=$(bonded_total)
    quorum=$(gov_param '.params.quorum // .quorum')
    if [ -z "$total" ] || [ "$total" = "0" ]; then
        echo "  could not read bonded stake -- is the node reachable?"
        return 1
    fi
    [ -z "$quorum" ] || [ "$quorum" = "null" ] && quorum="0.334"
    for name in "$@"; do
        a=$(addr_of "$name")
        if [ -z "$a" ]; then echo "  $name: NO SUCH KEY in this keyring"; continue; fi
        p=$(voter_power "$a")
        sum=$(echo "$sum + $p" | bc)
        share=$(pct "$p" "$total")
        printf "  %-12s %-46s %s%% of bonded\n" "$name" "$a" "$share"
    done
    combined=$(pct "$sum" "$total")
    qpct=$(echo "scale=4; $quorum * 100" | bc)
    printf "  combined %s%%   quorum needs %s%%\n" "$combined" "$qpct"
    [ "$(echo "$combined >= $qpct" | bc)" = "1" ]
}

# Poll a proposal to a terminal state.  Prints each transition, exits non-zero on anything but
# PASSED, so this can gate a deployment instead of being watched by a human.
gov_wait_proposal() {
    local id="$1" secs="${2:-420}" st prev="" waited=0
    while [ $waited -lt $secs ]; do
        st=$(qq q gov proposal "$id" -o json 2>/dev/null | jq -r '.proposal.status // empty')
        [ -z "$st" ] && st="(not found)"
        if [ "$st" != "$prev" ]; then
            printf "  %s  proposal %s: %s\n" "$(date +%H:%M:%S)" "$id" "$st"
            prev="$st"
        fi
        case "$st" in
            PROPOSAL_STATUS_PASSED)   return 0 ;;
            PROPOSAL_STATUS_REJECTED) echo "  proposal $id was REJECTED"; return 1 ;;
            PROPOSAL_STATUS_FAILED)   echo "  proposal $id FAILED to execute"; return 1 ;;
        esac
        sleep 6
        waited=$(( waited + 6 ))
    done
    echo "  proposal $id did not reach a terminal state within ${secs}s."
    echo "  A proposal that cannot reach quorum EXPIRES rather than failing -- check the tally:"
    echo "      scripts/gov_proposal_status.sh $id"
    return 1
}

# Submit a transaction and fail loudly on a non-zero code.  `qadenad tx` exits 0 for a transaction
# that was ACCEPTED, which is not the same as one that SUCCEEDED.
gov_tx() {
    local desc="$1"; shift
    local out hash code
    out=$(qq "$@" -y --output json --gas-prices "$minimum_gas_prices" --gas auto --gas-adjustment "$gas_adjustment" 2>&1)
    hash=$(echo "$out" | jq -r '.txhash // empty' 2>/dev/null)
    if [ -z "$hash" ]; then
        echo "  $desc: no txhash returned"
        echo "$out" | tail -3 | sed 's/^/    /'
        return 1
    fi
    qq q wait-tx "$hash" --timeout 60s > /dev/null 2>&1
    code=$(qq q tx "$hash" -o json 2>/dev/null | jq -r '.code // 0')
    if [ "$code" != "0" ]; then
        echo "  $desc: tx $hash failed with code $code"
        qq q tx "$hash" -o json 2>/dev/null | jq -r '.raw_log' | head -3 | sed 's/^/    /'
        return 1
    fi
    echo "  $desc: $hash"
    printf "%s" "$hash"
}
