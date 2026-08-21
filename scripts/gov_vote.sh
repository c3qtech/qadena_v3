#!/bin/zsh
#
# Vote on a proposal from one or more accounts, and report the tally that results.
#
#   gov_vote.sh <proposal-id> <yes|no|abstain|no_with_veto> [account ...]
#
# With no account named, votes as THIS NODE'S operator (config/node_params.json pioneer_id).  That
# is the intended use: each operator runs this on their own node, against a proposal id someone
# shared.  Keys live in the local keyring, so you can only ever vote as an account this node holds.
#
# ONE OPERATOR USUALLY CANNOT PASS ANYTHING, and that is by design: voting power follows the
# DELEGATOR, so an operator running a validator whose stake was delegated by someone else controls
# very little of it.  On this fleet the pioneer1 account holds 0.2475% while its validator holds
# 25%.  The per-account shares are printed before voting so a shortfall is visible immediately
# rather than showing up later as a proposal that quietly expired.

SCRIPT_DIR="${0:A:h}"
source "$SCRIPT_DIR/../scripts/setup_env.sh" > /dev/null 2>&1
source "$SCRIPT_DIR/gov_lib.sh"

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
# run where some accounts voted and one failed to sign.
if ! require_keys "${voters[@]}"; then
    exit 1
fi

# And the proposal has to be open, or every vote below fails one at a time with the same error.
pstatus=$(qq q gov proposal "$id" -o json 2>/dev/null | jq -r '.proposal.status // empty')
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
for name in "${voters[@]}"; do
    gov_tx "vote from $name" tx gov vote "$id" "$opt" --from "$name" > /dev/null || failed=1
done

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
