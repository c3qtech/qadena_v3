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

# THIS NODE'S OWN OPERATOR KEY.
#
# Governance is a multi-operator activity and these scripts run on the operator's OWN node, so the
# sensible default voter is this node's identity -- not a list of accounts that only exists on a
# test fleet where one machine holds everyone's keys.  $QADENAHOME/config/node_params.json is what
# the node itself uses to know which pioneer it is.
local_operator() {
    local f="$QADENAHOME/config/node_params.json" id=""
    [ -r "$f" ] && id=$(jq -r '.pioneer_id // empty' "$f" 2>/dev/null)
    # Fall back to the moniker, which is normally the same name.
    [ -z "$id" ] && id=$(grep -a '^moniker' "$QADENAHOME/config/config.toml" 2>/dev/null | sed -e 's/.*= *["'"'"']\([^"'"'"']*\)["'"'"'].*/\1/')
    printf "%s" "$id"
}

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

# account_power <keyname> -> "<floor> <ceiling>" in aqdn.
#
# VOTING POWER IS STAKED TOKENS ONLY -- a liquid balance counts for nothing, however large. The
# treasury here holds ~48x the entire bonded supply in liquid aqdn and would have ZERO say if it had
# not delegated.
#
# There are TWO ways an account has power, and counting only the first understates an operator by
# two orders of magnitude:
#
#   own delegations        what the account itself staked.  A delegator's vote OVERRIDES its
#                          validator for that portion.
#   validator operator     if the account operates a validator, its vote carries that validator's
#                          ENTIRE delegated stake, minus whatever delegators vote for themselves.
#
# Measured on this fleet: pioneer1 self-delegates 0.2475%, but voting from pioneer1 alone put
# 25.0000% of bonded stake on the proposal, because it operates a 25% validator and the treasury
# had not voted. When the treasury DOES vote, its delegation is subtracted from every validator and
# each operator falls back to its self-delegation. Both are correct; which applies depends on who
# else votes, so both are reported.
#
#   floor    what this account carries if every other delegator votes independently
#   ceiling  what it carries if none of them do
account_power() {
    local name="$1" a v own valtok selfd othr ceiling
    a=$(addr_of "$name")
    [ -z "$a" ] && { printf "0 0"; return 1 }
    own=$(voter_power "$a")
    v=$(qq keys show "$name" --bech val -a 2>/dev/null)
    valtok=0
    if [ -n "$v" ]; then
        valtok=$(qq q staking validator "$v" -o json 2>/dev/null | jq -r '.validator.tokens // .tokens // empty')
        [ -z "$valtok" ] && valtok=0
    fi
    if [ "$valtok" != "0" ]; then
        # Our self-delegation is already inside valtok; delegations to OTHER validators add on top.
        selfd=$(qq q staking delegation "$a" "$v" -o json 2>/dev/null \
                | jq -r '.delegation_response.balance.amount // .balance.amount // 0')
        [ -z "$selfd" ] && selfd=0
        othr=$(echo "$own - $selfd" | bc)
        ceiling=$(echo "$valtok + $othr" | bc)
    else
        ceiling="$own"
    fi
    printf "%s %s" "$own" "$ceiling"
}

# pct <part> <whole># pct <part> <whole> -- percentage as a plain decimal string, "0" if the inputs are unusable.
pct() {
    [ -z "$1" ] || [ -z "$2" ] || [ "$2" = "0" ] && { echo 0; return }
    echo "scale=4; $1 * 100 / $2" | bc 2>/dev/null || echo 0
}

# DOES THIS NODE ACTUALLY HOLD THE KEY?
#
# A governance vote is signed locally, so the account must exist in THIS node's keyring -- being the
# operator of a validator does not put a key on the box.  Checked BEFORE anything is broadcast, so a
# missing key produces instructions instead of a signing error midway through a multi-account run.
have_key() { qq keys show "$1" -a > /dev/null 2>&1 }

# Note: `keys list -o json` is NOT valid (cosmos wants --output json); -o is parsed as a shorthand
# flag and the command fails, which silently produced an empty key list here more than once.
list_keys() { qq keys list --output json 2>/dev/null | jq -r '.[].name' 2>/dev/null }

explain_missing_key() {
    local name="$1" backend
    # client.toml quotes with either " or ' depending on how it was written; matching only one
    # left the whole line in place of the value.
    backend=$(grep -a 'keyring-backend' "$QADENAHOME/config/client.toml" 2>/dev/null | sed -e 's/.*= *["'"'"']\([^"'"'"']*\)["'"'"'].*/\1/')
    echo "  '$name' is NOT in this node's keyring (backend: ${backend:-unknown})."
    echo
    echo "  A vote is signed locally, so the key has to be on THIS machine.  Add it with one of:"
    echo "      $qadenabin/qadenad --home $QADENAHOME keys add $name --recover"
    echo "          then paste the mnemonic when prompted"
    echo "      $qadenabin/qadenad --home $QADENAHOME keys add $name --ledger"
    echo "          for a hardware wallet"
    echo "      $qadenabin/qadenad --home $QADENAHOME keys import $name <armored-file>"
    echo "          for a backup exported with 'keys export'"
    echo
    echo "  Then confirm with:"
    echo "      $qadenabin/qadenad --home $QADENAHOME keys show $name -a"
    local have
    have=$(list_keys | tr '\n' ' ')
    [ -n "$have" ] && echo "  keys this node currently holds: $have"
}

# require_keys <name...> -- 0 only if every name is present locally.
require_keys() {
    local name missing=0
    for name in "$@"; do
        if ! have_key "$name"; then
            explain_missing_key "$name"
            missing=1
        fi
    done
    return $missing
}

addr_of() { qq keys show "$1" -a 2>/dev/null }

# Report whether the named accounts can clear quorum, WITHOUT submitting anything.
# Returns 0 if they can, 1 if they cannot.
# ALL ARITHMETIC GOES THROUGH bc.  Stake here is ~1e25 aqdn and zsh's $(( )) is 64-bit: it reports
# "number truncated after 20 digits" and yields garbage, which first showed up as every voter having
# 0.00% of bonded stake -- a number that looks like a real answer.
gov_can_reach_quorum() {
    local total quorum floor_sum=0 ceil_sum=0 name pair own ceil qpct fpct cpct is_val
    total=$(bonded_total)
    quorum=$(gov_param '.params.quorum // .quorum')
    if [ -z "$total" ] || [ "$total" = "0" ]; then
        echo "  could not read bonded stake -- is the node reachable?"
        return 1
    fi
    [ -z "$quorum" ] || [ "$quorum" = "null" ] && quorum="0.334"
    for name in "$@"; do
        if ! have_key "$name"; then echo "  $name: NO SUCH KEY in this keyring"; continue; fi
        pair=$(account_power "$name")
        own=${pair%% *}; ceil=${pair##* }
        floor_sum=$(echo "$floor_sum + $own" | bc)
        ceil_sum=$(echo "$ceil_sum + $ceil" | bc)
        if [ "$own" != "$ceil" ]; then
            printf "  %-12s staked %s%%  |  as validator operator up to %s%%\n" \
                "$name" "$(pct "$own" "$total")" "$(pct "$ceil" "$total")"
        else
            printf "  %-12s staked %s%%\n" "$name" "$(pct "$own" "$total")"
        fi
    done
    qpct=$(echo "scale=4; $quorum * 100" | bc)
    fpct=$(pct "$floor_sum" "$total")
    cpct=$(pct "$ceil_sum" "$total")
    if [ "$fpct" != "$cpct" ]; then
        printf "  combined %s%% .. %s%%   quorum needs %s%%\n" "$fpct" "$cpct" "$qpct"
        echo "    (the lower figure applies if every other delegator to your validator also votes)"
    else
        printf "  combined %s%%   quorum needs %s%%\n" "$cpct" "$qpct"
    fi
    [ "$(echo "$cpct >= $qpct" | bc)" = "1" ]
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
# PROGRESS GOES TO STDERR, THE HASH GOES TO STDOUT.
#
# Both used to go to stdout, so any caller that captured the hash also swallowed the progress line
# -- and a caller that wanted the progress had to discard the hash.  gov_vote.sh did the latter and
# printed nothing at all per vote.
gov_tx() {
    local desc="$1"; shift
    local out hash code
    out=$(qq "$@" -y --output json --gas-prices "$minimum_gas_prices" --gas auto --gas-adjustment "$gas_adjustment" 2>&1)
    # EXTRACT THE HASH, DO NOT PARSE THE WHOLE STREAM AS JSON.  `qadenad tx` prints a human line
    # ("gas estimate: 88012") before the JSON object, so `jq -r .txhash` over the combined output
    # fails with "Invalid numeric literal" -- and the transaction has ALREADY BEEN BROADCAST by
    # then, so the caller reports a failure for a vote that in fact landed.  Observed twice.
    hash=$(echo "$out" | sed -n 's/.*"txhash":"\([0-9A-Fa-f]*\)".*/\1/p' | head -1)
    if [ -z "$hash" ]; then
        echo "  $desc: no txhash returned" >&2
        echo "$out" | tail -3 | sed 's/^/    /' >&2
        return 1
    fi
    qq q wait-tx "$hash" --timeout 60s > /dev/null 2>&1
    # `qadenad tx` exits 0 for a transaction that was ACCEPTED, which is not the same as one that
    # SUCCEEDED -- the result code only exists once it is in a block.
    code=$(qq q tx "$hash" -o json 2>/dev/null | jq -r '.code // 0')
    if [ "$code" != "0" ]; then
        echo "  $desc: FAILED with code $code (tx $hash)" >&2
        qq q tx "$hash" -o json 2>/dev/null | jq -r '.raw_log' | head -3 | sed 's/^/    /' >&2
        return 1
    fi
    echo "  $desc: ok ($hash)" >&2
    printf "%s" "$hash"
}
