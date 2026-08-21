#!/bin/zsh
#
# What is happening to a governance proposal, and can it actually pass?
#
#   gov_proposal_status.sh            list proposals still in a voting period
#   gov_proposal_status.sh <id>       status, tally, and distance from quorum/threshold
#
# THE TALLY IS THE POINT.  A proposal that cannot reach quorum does not fail, it EXPIRES -- so
# "still in voting period" looks identical whether it is about to pass or was never going to.
# Exits non-zero unless the named proposal has PASSED, so it can gate a script.

SCRIPT_DIR="${0:A:h}"
source "$SCRIPT_DIR/../scripts/setup_env.sh" > /dev/null 2>&1
source "$SCRIPT_DIR/gov_lib.sh"

id="$1"

if [ -z "$id" ]; then
    echo "proposals in a voting period:"
    qq q gov proposals --status voting_period --output json 2>/dev/null \
      | jq -r '.proposals[]? | "  \(.id)  \(.title // .messages[0]["@type"])"' 2>/dev/null \
      || echo "  (none, or the query failed)"
    exit 0
fi

st=$(qq q gov proposal "$id" --output json 2>/dev/null | jq -r '.proposal.status // empty')
[ -z "$st" ] && { echo "proposal $id not found"; exit 1 }

echo "proposal $id: $st"

# The message is wrapped as {type, value} here, not the {"@type", ...} form jq examples assume --
# reading the wrong one printed "message: null" for a perfectly well-formed proposal.
qq q gov proposal "$id" --output json 2>/dev/null | jq -r '
  (.proposal.messages[0] // .messages[0]) as $m
  | ($m.type // $m["@type"] // "(none -- text proposal)") as $t
  | ($m.value // $m) as $v
  | "  message: \($t)" + (if $v.uniqueID then "\n  identity: \($v.uniqueID) / \($v.signerID) -> \($v.status)" else "" end)'

total=$(bonded_total)

# Tally as TEXT summed through bc.  $(( )) is 64-bit and these are ~1e25, so zsh reported
# "number truncated after 19 digits" and then printed a turnout of 0.00% and a yes-share of
# 1000000000.00% -- numbers wrong enough to be obvious only if you happen to look.
tally=$(qq q gov tally "$id" --output json 2>/dev/null | jq -c '.tally // empty')
[ -z "$tally" ] && tally=$(qq q gov proposal "$id" --output json 2>/dev/null | jq -c '.proposal.final_tally_result // empty')

yes=$(echo "$tally"     | jq -r '.yes_count // "0"')
no=$(echo "$tally"      | jq -r '.no_count // "0"')
abstain=$(echo "$tally" | jq -r '.abstain_count // "0"')
veto=$(echo "$tally"    | jq -r '.no_with_veto_count // "0"')
voted=$(echo "$yes + $no + $abstain + $veto" | bc)

quorum=$(gov_param '.params.quorum // .quorum')
thresh=$(gov_param '.params.threshold // .threshold')
[ -z "$quorum" ] || [ "$quorum" = "null" ] && quorum="0.334"
[ -z "$thresh" ] || [ "$thresh" = "null" ] && thresh="0.5"

turnout=$(pct "$voted" "$total")
qpct=$(echo "scale=4; $quorum * 100" | bc)
tpct=$(echo "scale=4; $thresh * 100" | bc)

printf "  bonded total : %s\n" "$total"
printf "  turnout      : %s%%   (quorum needs %s%%)\n" "$turnout" "$qpct"
printf "  yes / no / abstain / veto:\n    %s\n    %s\n    %s\n    %s\n" "$yes" "$no" "$abstain" "$veto"
if [ "$voted" != "0" ]; then
    printf "  yes of voted : %s%%   (threshold %s%%)\n" "$(pct "$yes" "$voted")" "$tpct"
fi

if [ "$st" = "PROPOSAL_STATUS_VOTING_PERIOD" ]; then
    if [ "$(echo "$turnout < $qpct" | bc)" = "1" ]; then
        echo
        echo "  WARNING: turnout is BELOW quorum.  Unless more stake votes, this proposal will"
        echo "  EXPIRE rather than fail -- it will simply stop being in a voting period."
        echo "  Add votes with:  scripts/gov_vote.sh $id yes <account> [<account>...]"
    fi
fi

[ "$st" = "PROPOSAL_STATUS_PASSED" ]
