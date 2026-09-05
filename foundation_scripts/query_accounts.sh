#!/bin/zsh
#
# What the foundation's accounts actually hold, on chain.
#
#   query_accounts.sh                              # sponsor accounts + all ten buckets
#   query_accounts.sh foundation-veritas-appsvr foundation-veritas-users
#   query_accounts.sh qadena1v2vqa779a5a4yxx4ehqqmeapmtwjqnfjnlpcgd
#   query_accounts.sh --buckets                    # just the ten allocation buckets
#   query_accounts.sh --csv > holdings.csv
#
# WHY A SCRIPT RATHER THAN `qadenad query bank balances`.
#
#   THE UNITS LIE TO YOU.  Balances come back in aqdn -- 100,000 QDN is 1e23 -- and comparing two
#   26-digit strings by eye is how an account gets funded twice.  Every figure here is converted
#   with Python ints (HARD RULE 3: no floats near an amount) and printed with separators.
#
#   LIQUID IS NOT EVERYTHING.  A bucket that has delegated its holdings shows a small `balances`
#   and looks empty.  Voting power follows BONDED stake, so an operator checking whether a bucket
#   can carry a vote must see the delegation, not the wallet.
#
#   THE NAMES ARE NOT ON THE NODE.  The buckets live in the COORDINATOR keyring (derive_launch_keys
#   --home), never the node's -- init.sh does `rm -rf` on $QADENAHOME.  So resolving a name needs
#   one keyring and the query needs another, and --keyring-backend is not valid on `query`.
#
#   1159 IS A PROPERTY OF THE ACCOUNT, NOT THE TRANSFER.  An account that is neither a qadena
#   wallet nor on the scanned-contract whitelist cannot SEND to anything uncredentialed, however
#   much it holds.  That is the difference between "funded" and "able to pay", and it is invisible
#   in a balance query, so it is a column here.
#
# READ-ONLY.  Nothing here signs, broadcasts, or writes to the chain.

HERE="${0:A:h}"
source "$HERE/../scripts/setup_env.sh" > /dev/null 2>&1 || true
SCRIPT_DIR="$HERE"          # setup_env.sh clobbers SCRIPT_DIR

QBIN="${qadenabin:-$HOME/qadena/bin}/qadenad"
NODE_HOME="${QADENAHOME:-$HOME/qadena}"
NODE="${QADENA_NODE:-tcp://localhost:26657}"
COORD_HOME=""
BACKEND="${QADENA_KEYRING_BACKEND:-test}"
KEYRING_PASSFILE=""
WANT=()
SHOW_BUCKETS=0
AS_CSV=0

# The ten allocation buckets, by the account names fill_launch_config.py's SLUG map produces.
# Kept in allocations.csv order so the output reads like the tokenomics table.
BUCKETS=(adoption wallet-incentive-pool ltr foundation grants personnel backers founders
         contingency pubsec nodeops qfi-pioneer1)
SPONSORS=(foundation-veritas-appsvr foundation-veritas-users)

usage() {
    print "Usage: query_accounts.sh [options] [name-or-address ...]"
    print ""
    print "  no arguments        the sponsor accounts and all ten buckets"
    print "  --buckets           only the allocation buckets"
    print "  --sponsors          only ${SPONSORS[*]}"
    print "  --csv               machine-readable, one row per account"
    print "  --coord-home <dir>  keyring holding the bucket names (derive_launch_keys.sh --home)."
    print "                      Only needed to resolve NAMES; addresses work without it."
    print "  --keyring-backend <b>   default $BACKEND"
    print "  --keyring-passfile <f>  read the keyring passphrase from a file"
    print "  --node <rpc>        default $NODE"
    exit ${1:-1}
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --buckets)          SHOW_BUCKETS=1; shift ;;
        --sponsors)         WANT+=("${SPONSORS[@]}"); shift ;;
        --csv)              AS_CSV=1; shift ;;
        --coord-home)       COORD_HOME="$2"; shift 2 ;;
        --keyring-backend)  BACKEND="$2"; shift 2 ;;
        --keyring-passfile) KEYRING_PASSFILE="$2"; shift 2 ;;
        --node)             NODE="$2"; shift 2 ;;
        --help|-h)          usage 0 ;;
        -*)                 print -u2 -- "unknown option: $1"; usage ;;
        *)                  WANT+=("$1"); shift ;;
    esac
done

(( SHOW_BUCKETS )) && WANT+=("${BUCKETS[@]}")
(( ${#WANT} )) || WANT=("${SPONSORS[@]}" "${BUCKETS[@]}")

[[ -n "$COORD_HOME" ]] || COORD_HOME="$NODE_HOME"

qq() { "$QBIN" --home "$NODE_HOME" "$@" --node "$NODE" }

# ASK ONLY IF A NAME ACTUALLY HAS TO BE RESOLVED.  Querying by address needs no keyring at all,
# and prompting for a passphrase this script may never use trains operators to type it reflexively.
KRPASS=""
need_keyring=0
for w in "${WANT[@]}"; do [[ "$w" == qadena1* ]] || need_keyring=1; done
if (( need_keyring )) && [[ "$BACKEND" == "file" ]]; then
    if [[ -n "$KEYRING_PASSFILE" ]]; then
        KRPASS=$(head -1 "$KEYRING_PASSFILE")
    else
        print -u2 "Resolving account NAMES needs the coordinator keyring at $COORD_HOME."
        print -u2 "This is the one passphrase derive_launch_keys.sh asked for."
        print -u2 -n "  passphrase (hidden, will not echo, read-only): "
        read -s KRPASS; print -u2 ""
    fi
fi
qk() {
    if [[ -n "$KRPASS" ]]; then
        { print -r -- "$KRPASS"; print -r -- "$KRPASS" } \
            | "$QBIN" --home "$COORD_HOME" --keyring-backend "$BACKEND" "$@"
    else
        "$QBIN" --home "$COORD_HOME" --keyring-backend "$BACKEND" "$@"
    fi
}

addr_of() {
    [[ "$1" == qadena1* ]] && { print -r -- "$1"; return 0 }
    local a
    a=$(qk keys show "$1" -a 2>/dev/null | tr -d '\r')
    [[ -n "$a" ]] || return 1
    print -r -- "$a"
}

# aqdn -> whole QDN with separators.  Python because these are 26-digit integers and the shell
# truncates past 20 -- the same overflow that made a stake computation come out negative.
# SEPARATORS ARE FOR HUMANS AND POISON FOR CSV.  "2,000,000" in a comma-separated file is three
# fields, so --csv gets its own formatter: plain digits, no grouping.
fmt_plain() { python3 -c "
import sys
v = int(sys.argv[1] or 0)
w, frac = divmod(v, 10**18)
print(str(w) + ('' if frac == 0 else f'.{frac:018d}'.rstrip('0')))" "$1" 2>/dev/null || print 0 }

fmt() { python3 -c "
import sys
v = int(sys.argv[1] or 0)
w, frac = divmod(v, 10**18)
print(f'{w:,}' + ('' if frac == 0 else f'.{frac:018d}'.rstrip('0')))" "$1" 2>/dev/null || print 0 }

# THE WHITELIST, FETCHED ONCE.  One query, not one per account.
WL=$(qq query qadena list-scanned-contract-whitelist --output json 2>/dev/null \
       | jq -r '.scannedContractWhitelist[]?.address' 2>/dev/null)

if (( AS_CSV )); then
    print "name,address,liquid_qdn,delegated_qdn,unbonding_qdn,total_qdn,whitelisted,exists"
else
    print ""
    printf "  %-22s %-14s %14s %14s %14s  %s\n" ACCOUNT ADDRESS LIQUID DELEGATED TOTAL AML
    printf "  %s\n" "$(printf '%.0s-' {1..92})"
fi

for name in "${WANT[@]}"; do
    addr=$(addr_of "$name") || {
        if (( AS_CSV )); then print "$name,,,,,,,no"
        else printf "  %-22s %s\n" "$name" "-- not in the keyring at $COORD_HOME"; fi
        continue
    }

    liquid=$(qq query bank balances "$addr" --output json 2>/dev/null \
               | jq -r '(.balances[]? | select(.denom=="aqdn") | .amount) // "0"')
    : ${liquid:=0}

    # DELEGATED IS SUMMED ACROSS VALIDATORS.  A bucket may be spread over the whole consortium,
    # and only the total tells you whether it can carry a vote.
    deleg=$(qq query staking delegations "$addr" --output json 2>/dev/null \
              | jq -r '.delegation_responses[]?.balance.amount // empty' | python3 -c "import sys; print(sum(int(x) for x in sys.stdin.read().split() or ['0']))" 2>/dev/null)
    : ${deleg:=0}
    unbond=$(qq query staking unbonding-delegations "$addr" --output json 2>/dev/null \
               | jq -r '.unbonding_responses[]?.entries[]?.balance // empty' | python3 -c "import sys; print(sum(int(x) for x in sys.stdin.read().split() or ['0']))" 2>/dev/null)
    : ${unbond:=0}

    total=$(python3 -c "print(int('${liquid:-0}')+int('${deleg:-0}')+int('${unbond:-0}'))" 2>/dev/null)

    if print -r -- "$WL" | grep -qx "$addr"; then wl=listed; else wl=NOT-listed; fi

    if (( AS_CSV )); then
        print "$name,$addr,$(fmt_plain $liquid),$(fmt_plain $deleg),$(fmt_plain $unbond),$(fmt_plain $total),$wl,yes"
    else
        # When the argument WAS an address there is no name to show, and printing the 44-char
        # bech32 in a 22-char column shifts every figure after it out of alignment.
        label="$name"
        [[ "$label" == qadena1* ]] && label="(by address)"
        printf "  %-22s %-14s %14s %14s %14s  %s\n" \
            "$label" "${addr:0:10}..${addr: -4}" \
            "$(fmt $liquid)" "$(fmt $deleg)" "$(fmt $total)" "$wl"
    fi
done

(( AS_CSV )) && exit 0

print ""
print "  LIQUID     spendable now.  DELEGATED bonded to validators -- this is what votes."
print "  TOTAL      liquid + delegated + unbonding."
print "  AML        'NOT-listed' means the account cannot SEND to anything uncredentialed"
print "             (code 1159), however much it holds.  Buckets are listed at genesis;"
print "             accounts created afterwards are not, and need a governance proposal."
print ""
