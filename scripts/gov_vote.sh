#!/bin/zsh
#
# Vote on a proposal from one or more accounts, and report the tally that results.
#
#   gov_vote.sh <proposal-id> <yes|no|abstain|no_with_veto> <account> [<account>...]
#
# Voting from SEVERAL accounts is the normal case, not the exception: voting power follows the
# DELEGATOR, so on a fleet with evenly split stake no single pioneer can reach the 33.4% quorum.
# Reports each account's share before voting so a shortfall is visible up front rather than as a
# proposal that quietly expires.

SCRIPT_DIR="${0:A:h}"
source "$SCRIPT_DIR/../scripts/setup_env.sh" > /dev/null 2>&1
source "$SCRIPT_DIR/gov_lib.sh"

id="$1"; opt="$2"; shift 2 2>/dev/null
if [ -z "$id" ] || [ -z "$opt" ] || [ $# -eq 0 ]; then
    echo "Usage: gov_vote.sh <proposal-id> <yes|no|abstain|no_with_veto> <account> [<account>...]"
    exit 1
fi

echo "voting $opt on proposal $id from: $*"
gov_can_reach_quorum "$@"
reachable=$?

failed=0
for name in "$@"; do
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
    echo "NOTE: the accounts voted here do not by themselves reach quorum.  The proposal will"
    echo "      expire unless other stake votes as well."
fi
if [ $failed -ne 0 ]; then
    echo
    echo "at least one vote FAILED -- see above"
    exit 1
fi
exit 0
