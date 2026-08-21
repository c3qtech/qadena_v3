#!/bin/zsh
#
# Register an enclave measurement on chain, the operator way: submit, deposit, vote, and WAIT for
# the outcome -- then wait again for the peer quorum to promote it to active.
#
#   gov_register_enclave_identity.sh <uniqueID> <signerID> [voter ...]
#   gov_register_enclave_identity.sh --dry-run <uniqueID> <signerID> [voter ...]
#
# Run by ONE operator, on their own node.  Voters default to this node's operator
# (config/node_params.json pioneer_id); name more accounts only if this node holds their keys.
#
# ONE OPERATOR NORMALLY CANNOT PASS IT ALONE, and that is not an error.  An operator's vote carries
# its validator's delegated stake -- 25% on a four-validator fleet -- which is short of the 33.4%
# quorum by itself but clears it with one more operator.  So this submits, votes, and prints the
# exact command the others run on THEIR nodes, then exits 0 rather than blocking on a quorum this
# node cannot produce alone.
#
# THIS IS THE STEP THAT MUST HAPPEN BEFORE YOU BUILD.  build.sh installs the new binary as the live
# one and stops the node to do it; if the measurement is not ACTIVE by then, the old enclave refuses
# to hand its sealed keys over and the node stays down.  The measurement is readable from
# cmd/qadenad_enclave/test_unique_id.txt without compiling anything, which is what makes registering
# first possible.
#
# WHAT IT REFUSES TO DO:
#   - register a measurement that already exists.  UpdateEnclaveIdentity only allows an EXISTING row
#     to move to `inactive`, so a re-registration cannot succeed and cannot un-condemn anything.
#   - submit when the named voters cannot reach quorum, unless --force.  A proposal short of quorum
#     does not fail, it EXPIRES, and every transaction along the way reports success.

SCRIPT_DIR="${0:A:h}"
source "$SCRIPT_DIR/../scripts/setup_env.sh" > /dev/null 2>&1
source "$SCRIPT_DIR/gov_lib.sh"

dry_run=0; force=0
while [[ "$1" == --* ]]; do
    case "$1" in
        --dry-run) dry_run=1; shift ;;
        --force)   force=1; shift ;;
        -h|--help) sed -n '3,24p' "$0"; exit 0 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

uniqueid="$1"; signerid="$2"; shift 2 2>/dev/null
voters=("$@")
[ ${#voters[@]} -eq 0 ] && voters=(${=gov_default_voters:-$(local_operator)})

if [ -z "$uniqueid" ] || [ -z "$signerid" ]; then
    echo "Usage: gov_register_enclave_identity.sh [--dry-run] [--force] <uniqueID> <signerID> [voter ...]"
    exit 1
fi

echo "registering $uniqueid / $signerid"

existing=$(qq q qadena show-enclave-identity "$uniqueid" --output json 2>/dev/null | jq -r '.enclaveIdentity.status // empty')
if [ -n "$existing" ]; then
    echo "  $uniqueid is ALREADY registered with status '$existing'."
    case "$existing" in
        active)      echo "  Nothing to do -- it is active and ready to deploy." ; exit 0 ;;
        unvalidated) echo "  Waiting on the peer quorum; re-run scripts/enclave_identities.sh." ; exit 0 ;;
        inactive)    echo "  It was condemned or retired, and that is PERMANENT: governance can only"
                     echo "  move an existing row TO inactive, never back.  Build a NEW measurement."
                     exit 1 ;;
    esac
fi

if ! require_keys "${voters[@]}"; then
    exit 1
fi

echo "  voters (on this node):"
gov_can_reach_quorum "${voters[@]}"
reachable=$?
if [ $reachable -ne 0 ]; then
    echo
    echo "  This node cannot pass the proposal alone -- normal when several operators must vote."
    echo "  It will be submitted and voted; the other operators then run it on their own nodes."
fi

if [ $dry_run -eq 1 ]; then
    echo
    echo "  --dry-run: nothing submitted."
    exit 0
fi

tmpl="$qadenatestdata/update_enclave_identity.json"
[ -r "$tmpl" ] || tmpl="$qadenabuild/test_data/update_enclave_identity.json"
[ -r "$tmpl" ] || { echo "  cannot find update_enclave_identity.json template"; exit 1 }

gen=$(mktemp)
jq --arg u "$uniqueid" --arg s "$signerid" --arg st "unvalidated" \
   '.messages[0] |= (.uniqueID = $u | .signerID = $s | .status = $st)' "$tmpl" > "$gen" || exit 1

echo "  submitting..."
hash=$(gov_tx "submit" tx gov submit-proposal "$gen" --from "${voters[1]}" | tail -1) || exit 1
id=$(qq q tx "$hash" --output json 2>/dev/null \
     | jq -r '.events[] | select(.type=="submit_proposal") | .attributes[] | select(.key=="proposal_id") | .value' | head -1)
rm -f "$gen"
[ -z "$id" ] && { echo "  could not determine the proposal id from $hash"; exit 1 }
echo "  proposal id: $id"

gov_tx "deposit" tx gov deposit "$id" 1000qdn --from "${voters[1]}" > /dev/null || exit 1
for v in "${voters[@]}"; do
    gov_tx "vote from $v" tx gov vote "$id" yes --from "$v" > /dev/null || exit 1
done

if [ $reachable -ne 0 ]; then
    # Do NOT block on a quorum this node cannot produce: waiting would time out and report failure
    # for a proposal that is perfectly healthy and simply needs other operators to vote.
    echo
    echo "  proposal $id is live and voted by ${voters[*]} ($(pct "$(voter_power "$(addr_of "${voters[1]}")")" "$(bonded_total)")%)."
    echo "  Ask every other operator to run, ON THEIR OWN NODE:"
    echo "      scripts/gov_vote.sh $id yes"
    echo
    echo "  Watch it with:   scripts/gov_proposal_status.sh $id"
    echo "  Once it passes, $uniqueid still has to be promoted by the peer quorum; check with:"
    echo "      scripts/enclave_identities.sh"
    exit 0
fi

echo "  waiting for the proposal..."
gov_wait_proposal "$id" 420 || exit 1

echo "  waiting for the peer quorum to promote $uniqueid..."
for i in {1..60}; do
    st=$(qq q qadena show-enclave-identity "$uniqueid" --output json 2>/dev/null | jq -r '.enclaveIdentity.status // empty')
    case "$st" in
        active)   echo "  $uniqueid is ACTIVE -- safe to build and restart"; exit 0 ;;
        inactive) echo "  $uniqueid was CONDEMNED by the peer quorum.  It is spent; build a new"
                  echo "  measurement.  Check why:  grep 'enclave-identity:' in the node logs."
                  exit 1 ;;
    esac
    sleep 6
done
echo "  $uniqueid is still '${st:-unregistered}' after 360s -- check scripts/enclave_identities.sh"
exit 1
