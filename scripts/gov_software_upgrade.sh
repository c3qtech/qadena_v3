#!/bin/zsh
# Submit, vote, and wait out ONE governance proposal that schedules a cosmovisor binary swap --
# optionally registering a new enclave measurement in the same proposal.
#
#   gov_software_upgrade.sh --plan v1.1.23 [--height N | --margin SECS]
#                           [--unique-id <id> --signer-id <id>]        # chain+enclave upgrade
#                           [--expedited] [--voters "p1 p2 ..."]
#
# WHY ONE PROPOSAL AND NOT TWO.  gov v1 executes every message of a passed proposal atomically,
# and the two messages have naturally different effective times: MsgUpdateEnclaveIdentity lands
# the moment the proposal PASSES (registering the measurement unvalidated -- the only status the
# chain accepts for a new row; quorum promotion to active follows), while MsgSoftwareUpgrade only
# SCHEDULES height H.  So the measurement is registered, promoted and active well before any
# binary carrying it starts -- correct sequencing with nothing to coordinate.
#
# THE HEIGHT IS THE DANGEROUS PARAMETER.  Too close and the vote finishes after the chain passed
# H: the plan is dead and must be MsgCancelUpgrade'd.  Computed by default from the chain's own
# voting period and a MEASURED block time (gov_lib.sh gov_upgrade_height); --height overrides for
# operators who know better.  On failure this script prints the cancel recipe rather than leaving
# the operator to derive it mid-incident.
#
# WHAT THIS SCRIPT DOES NOT DO: build, package, distribute, or stage binaries.  That is
# upgrade_fleet.sh, which calls this as its governance step.  Submitting a plan
# for binaries that are not staged everywhere halts the fleet at H -- the preflight there exists
# for that; going around it means you have checked staging yourself.

SCRIPT_DIR="${0:A:h}"
source "$SCRIPT_DIR/setup_env.sh" > /dev/null 2>&1
source "$SCRIPT_DIR/gov_lib.sh"

PLAN=""; HEIGHT=""; MARGIN=180; UNIQUE=""; SIGNER=""; EXPEDITED=0; VOTERS=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --plan)      PLAN="$2"; shift 2 ;;
        --height)    HEIGHT="$2"; shift 2 ;;
        --margin)    MARGIN="$2"; shift 2 ;;
        --unique-id) UNIQUE="$2"; shift 2 ;;
        --signer-id) SIGNER="$2"; shift 2 ;;
        --expedited) EXPEDITED=1; shift ;;
        --voters)    VOTERS="$2"; shift 2 ;;
        --help)      sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "gov_software_upgrade.sh: unknown option $1" >&2; exit 1 ;;
    esac
done
[[ -n "$PLAN" ]] || { echo "gov_software_upgrade.sh: --plan is required (e.g. v1.1.23)" >&2; exit 1 }
if [[ -n "$UNIQUE" && -z "$SIGNER" ]] || [[ -z "$UNIQUE" && -n "$SIGNER" ]]; then
    echo "gov_software_upgrade.sh: --unique-id and --signer-id go together" >&2; exit 1
fi

say() { echo "gov_software_upgrade.sh: $*" }
die() { echo "gov_software_upgrade.sh: FAIL: $*" >&2; exit 1 }

# ---------------------------------------------------------------------------------------------
if [[ -z "$HEIGHT" ]]; then
    say "computing the upgrade height (voting period + ${MARGIN}s margin, measured block time)"
    HEIGHT=$(gov_upgrade_height "$MARGIN")
    [[ -n "$HEIGHT" ]] || die "could not compute an upgrade height -- is the local RPC answering?"
fi
now_h=$(qq status 2>&1 | grep -oE '"latest_block_height":"[0-9]+"' | grep -oE '[0-9]+' | head -1)
say "plan $PLAN at height $HEIGHT (chain is at ${now_h:-?})"
[[ -n "$now_h" && "$HEIGHT" -gt "$now_h" ]] || die "height $HEIGHT is not in the future"

# ---------------------------------------------------------------------------------------------
# The template, patched.  Two templates rather than one with a deleted message: a jq `del()` that
# silently failed would submit an enclave registration nobody intended.
tname="software_upgrade.json"
[[ -n "$UNIQUE" ]] && tname="software_upgrade_with_enclave.json"
tmpl=""
for d in "$qadenatestdata" "$qadenabuild/test_data" "$QADENAHOME/test_data" ~/qv3/test_data; do
    [[ -n "$d" && -r "$d/$tname" ]] && { tmpl="$d/$tname"; break }
done
[[ -n "$tmpl" ]] || die "cannot find $tname in test_data locations"

gen=$(mktemp)
if [[ -n "$UNIQUE" ]]; then
    jq --arg u "$UNIQUE" --arg s "$SIGNER" --arg p "$PLAN" --arg h "$HEIGHT" \
       --argjson e $( ((EXPEDITED)) && echo true || echo false ) \
       '.messages[0].uniqueID=$u | .messages[0].signerID=$s
        | .messages[1].plan.name=$p | .messages[1].plan.height=$h
        | .expedited=$e' "$tmpl" > "$gen" || die "template patch failed"
else
    jq --arg p "$PLAN" --arg h "$HEIGHT" \
       --argjson e $( ((EXPEDITED)) && echo true || echo false ) \
       '.messages[0].plan.name=$p | .messages[0].plan.height=$h | .expedited=$e' "$tmpl" > "$gen" \
        || die "template patch failed"
fi

# ---------------------------------------------------------------------------------------------
voters=(${=VOTERS:-$(local_operator)})
require_keys "${voters[@]}" || exit 1

say "submitting..."
hash=$(gov_tx "submit" tx gov submit-proposal "$gen" --from "${voters[1]}" | tail -1) || { rm -f "$gen"; die "submit failed" }
rm -f "$gen"
id=$(gov_proposal_id_of_tx "$hash")
[[ -n "$id" ]] || die "could not read the proposal id from tx $hash"
say "proposal id: $id"

gov_tx "deposit" tx gov deposit "$id" 1000qdn --from "${voters[1]}" > /dev/null || die "deposit failed"
for v in "${voters[@]}"; do
    gov_tx "vote from $v" tx gov vote "$id" yes --from "$v" > /dev/null || die "vote from $v failed"
done

# For an UPGRADE the wait cannot be optional: the height clock is running.  If quorum needs other
# operators, say exactly what they must run and keep waiting.
if ! gov_can_reach_quorum "${voters[@]}"; then
    say "these voters cannot reach quorum alone -- other operators must run:"
    say "    scripts/gov_vote.sh $id yes"
    say "waiting regardless (the plan height is $HEIGHT and the clock is running)"
fi

wait_secs=$(( MARGIN + 600 ))
if ! gov_wait_proposal "$id" "$wait_secs"; then
    die "proposal $id did not pass.  If it PASSED LATE or the chain has meanwhile passed height \
$HEIGHT, the plan is dead weight -- cancel it before it halts the fleet at the next restart: \
submit a proposal carrying /cosmos.upgrade.v1beta1.MsgCancelUpgrade (authority \
qadena10d07y265gmmuvt4z0w9aw880jnsr700j5pc4em)."
fi

say "PASSED.  Plan $PLAN is scheduled at height $HEIGHT."
[[ -n "$UNIQUE" ]] && say "enclave identity $UNIQUE registered (unvalidated) -- promotion to active must complete BEFORE $HEIGHT."
exit 0
