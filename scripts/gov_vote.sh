#!/bin/zsh
#
# Vote on a proposal from one or more accounts, and report the tally that results.
#
#   gov_vote.sh <proposal-id> <yes|no|abstain|no_with_veto> [account ...]
#
#   --ledger              sign on a hardware wallet; the key never exists on this machine
#   --generate-only       write an UNSIGNED tx and stop, for signing on an airgapped box
#   --address <addr>      the voter's address, when this node holds no key for it
#   --import              prompt for the mnemonic and add the key before voting
#   --forget              delete the key from the keyring after voting (pairs with --import)
#
# HOW THE KEY REACHES THE NODE IS A REAL DECISION.  The operator account key votes AND controls the
# stake -- delegate, undelegate, withdraw, edit-validator -- so keeping it hot on a validator is an
# exposure out of proportion to casting a vote.  In order of preference:
#
#   --ledger          the key stays on the device and the vote is confirmed there
#   --generate-only   the key never touches the validator at all: sign elsewhere, broadcast anywhere
#   --import          last resort.  The mnemonic is typed in and written to the backend configured
#                     in client.toml -- with backend "test" that is PLAINTEXT ON DISK.  Pair with
#                     --forget, and note that deleting a key file is not shredding it.
#
# With no account named, votes as THIS NODE'S operator (config/node_params.json pioneer_id).  That
# is the intended use: each operator runs this on their own node, against a proposal id someone
# shared.  Keys live in the local keyring, so you can only ever vote as an account this node holds.
#
# WHAT YOUR VOTE WEIGHS.  Only STAKED tokens count -- a liquid balance is worth nothing, however
# large.  An operator gets power two ways:
#
#   what the account itself delegated, and
#   if the account operates a validator, that validator's ENTIRE delegated stake, minus whatever
#   delegators vote for themselves (a delegator's own vote overrides its validator).
#
# So the same account can be worth 0.2475% or 25% of the chain depending on who else votes.  Both
# figures are printed before voting.  Measured here: pioneer1 alone put 25.0000% on a proposal the
# treasury ignored; pioneer1 + pioneer2 reached 50.0000%, past the 33.4% quorum -- while on a
# proposal the treasury DID vote on, the same two accounts carried only their self-delegations.

SCRIPT_DIR="${0:A:h}"
source "$SCRIPT_DIR/../scripts/setup_env.sh" > /dev/null 2>&1
source "$SCRIPT_DIR/gov_lib.sh"

use_ledger=0; generate_only=0; do_import=0; do_forget=0; explicit_addr=""
args=()
while [ $# -gt 0 ]; do
    case "$1" in
        --ledger)        use_ledger=1; shift ;;
        --generate-only) generate_only=1; shift ;;
        --import)        do_import=1; shift ;;
        --forget)        do_forget=1; shift ;;
        --address)       explicit_addr="$2"; shift 2 ;;
        -h|--help)       sed -n '3,32p' "$0"; exit 0 ;;
        *)               args+=("$1"); shift ;;
    esac
done
set -- "${args[@]}"

id="$1"; opt="$2"; shift 2 2>/dev/null
voters=("$@")
if [ ${#voters[@]} -eq 0 ]; then
    voters=($(local_operator))
    [ -z "${voters[1]}" ] && {
        echo "could not determine this node's operator from $QADENAHOME/config/node_params.json"
        echo "Usage: gov_vote.sh <proposal-id> <yes|no|abstain|no_with_veto> [account ...]"
        exit 1
    }
fi
if [ -z "$id" ] || [ -z "$opt" ]; then
    echo "Usage: gov_vote.sh <proposal-id> <yes|no|abstain|no_with_veto> [account ...]"
    echo "  with no account, votes as this node's operator: $(local_operator)"
    exit 1
fi

echo "voting $opt on proposal $id as: ${voters[*]}"

# Checked before anything is broadcast: a missing key should produce instructions, not a partial
# run where some accounts voted and one failed to sign.  Skipped for --ledger (the key is on the
# device) and --generate-only (nothing is signed here at all).
if [ $generate_only -eq 0 ] && [ $use_ledger -eq 0 ]; then
    if [ $do_import -eq 1 ]; then
        backend=$(grep -a 'keyring-backend' "$QADENAHOME/config/client.toml" 2>/dev/null \
                  | sed -e 's/.*= *["'"'"']\([^"'"'"']*\)["'"'"'].*/\1/')
        for name in "${voters[@]}"; do
            if have_key "$name"; then
                echo "  '$name' is already in the keyring; --import not needed for it"
                continue
            fi
            echo
            echo "  Importing '$name' into the '${backend:-unknown}' keyring."
            if [ "$backend" = "test" ]; then
                echo "  WARNING: the 'test' backend stores keys UNENCRYPTED ON DISK.  For an operator"
                echo "  key that also controls stake, prefer --ledger or --generate-only.  If you"
                echo "  continue, pair this with --forget -- deleting a key file is not shredding it."
            fi
            echo "  qadenad will prompt for the mnemonic:"
            qq keys add "$name" --recover || { echo "  import failed"; exit 1; }
        done
    fi
    if ! require_keys "${voters[@]}"; then
        echo
        echo "  If this node should NOT hold the key:"
        echo "      $0 $id $opt --ledger"
        echo "          sign on a hardware wallet"
        echo "      $0 $id $opt --generate-only --address <qadena1...>"
        echo "          write an unsigned tx to sign on an airgapped machine"
        echo "      $0 $id $opt --import --forget"
        echo "          type the mnemonic, vote, then remove the key again"
        exit 1
    fi
fi

# And the proposal has to be open, or every vote below fails one at a time with the same error.
pstatus=$(qq q gov proposal "$id" --output json 2>/dev/null | jq -r '.proposal.status // empty')
if [ -z "$pstatus" ]; then
    echo "  proposal $id does not exist on this chain"
    exit 1
fi
if [ "$pstatus" != "PROPOSAL_STATUS_VOTING_PERIOD" ]; then
    echo "  proposal $id is $pstatus -- not open for voting"
    [ "$pstatus" = "PROPOSAL_STATUS_DEPOSIT_PERIOD" ] && \
        echo "  it still needs its minimum deposit:  qadenad tx gov deposit $id <amount> --from <you>"
    exit 1
fi

gov_can_reach_quorum "${voters[@]}"
reachable=$?

failed=0

if [ $generate_only -eq 1 ]; then
    # NOTHING IS BROADCAST AND NOTHING IS SIGNED HERE -- that is the entire point: the signing key
    # never has to exist on the validator.
    from="${explicit_addr:-$(addr_of "${voters[1]}")}"
    if [ -z "$from" ]; then
        echo "  --generate-only needs --address <qadena1...> when this node holds no key for the voter"
        exit 1
    fi
    chain=$(qq status 2>/dev/null | jq -r '.node_info.network // .NodeInfo.network // empty')
    out="/tmp/govvote-${id}-${opt}.json"
    # FIXED GAS, NOT `--gas auto`.  Simulation needs a signer, so `--gas auto` with
    # --generate-only fails -- and it fails with "no key name or address provided; have you
    # forgotten the --from flag?", which sends you looking at the wrong thing entirely.  200000 is
    # ample for a MsgVote; override with GOV_VOTE_GAS if a chain disagrees.
    if ! qq tx gov vote "$id" "$opt" --from "$from" --generate-only \
            --gas-prices "$minimum_gas_prices" --gas "${GOV_VOTE_GAS:-200000}" > "$out" 2>/tmp/govvote.err; then
        echo "  could not build the unsigned transaction:"
        tail -3 /tmp/govvote.err | sed 's/^/    /'
        exit 1
    fi
    echo "  unsigned transaction: $out"
    echo
    echo "  1. copy it to the machine holding the key and sign OFFLINE:"
    echo "       qadenad tx sign $out --from <key> --chain-id ${chain:-<chain-id>} \\"
    echo "         --account-number <n> --sequence <n> --offline > signed.json"
    echo "  2. broadcast from anywhere with RPC access:"
    echo "       qadenad tx broadcast signed.json"
    echo
    # THE TWO VALUES OFFLINE SIGNING CANNOT DO WITHOUT, and both are easy to get wrong:
    #
    #   the subcommand is `q auth account`, NOT `q account` -- the latter is not a subcommand at
    #   all, so it silently falls through to the query help and prints nothing.
    #
    #   account_number is ABSENT from the JSON when it is 0 (proto3 omits zero values), and a
    #   genesis account really can be number 0 -- pioneer1 here is.  Defaulting to "0" rather than
    #   treating absence as an error is the difference between a working signature and
    #   `strconv.ParseUint: parsing "": invalid syntax` three steps later.
    acct=$(qq q auth account "$from" --output json 2>/dev/null \
           | jq -r '(.account.value.account_number // .account.account_number // "0")' 2>/dev/null)
    seqno=$(qq q auth account "$from" --output json 2>/dev/null \
           | jq -r '(.account.value.sequence // .account.sequence // "0")' 2>/dev/null)
    if [ -n "$seqno" ]; then
        echo "  account-number and sequence for $from:"
        echo "       --account-number ${acct:-0} --sequence $seqno"
        echo
        echo "  NOTE: the sequence is only valid until this account sends its next transaction, and"
        echo "  the proposal must still be OPEN when you broadcast -- a vote arriving after the"
        echo "  voting period ends is rejected with 'inactive proposal', not a signing error."
    else
        echo "  could not read account-number/sequence; try: qadenad q auth account $from --output json"
    fi
    exit 0
fi

ledger_flag=()
[ $use_ledger -eq 1 ] && ledger_flag=(--ledger)
for name in "${voters[@]}"; do
    gov_tx "vote from $name" tx gov vote "$id" "$opt" --from "$name" "${ledger_flag[@]}" > /dev/null || failed=1
done

if [ $do_forget -eq 1 ]; then
    for name in "${voters[@]}"; do
        if qq keys delete "$name" -y > /dev/null 2>&1; then
            echo "  removed '$name' from the keyring (--forget)"
        else
            echo "  WARNING: could not remove '$name' from the keyring -- it is still there"
        fi
    done
fi

echo
# Informational: the proposal will usually still be in its voting period here.  The exit code
# reflects whether the VOTES landed, not whether the proposal has passed -- a vote that succeeded on
# a proposal still being voted on is not a failure, and treating it as one made this script unusable
# in a pipeline.
"$SCRIPT_DIR/gov_proposal_status.sh" "$id" || true

if [ $reachable -ne 0 ]; then
    echo
    echo "NOTE: this vote alone does not reach quorum -- expected when several operators must vote."
    echo "      The proposal EXPIRES rather than failing if turnout stays short, so ask the other"
    echo "      operators to run, on their own nodes:"
    echo "          scripts/gov_vote.sh $id $opt"
fi
if [ $failed -ne 0 ]; then
    echo
    echo "at least one vote FAILED -- see above"
    exit 1
fi
exit 0
