#!/bin/zsh
#
# Put an address on the scanned-contract whitelist, the operator way: submit, deposit, vote, and
# either WAIT for the outcome or hand the remaining operators the exact command they must run.
#
#   gov_whitelist_bank_send.sh [--from <depositor>] [--reason TEXT] [--code-id N] \
#                              <address-or-key> [voter ...]
#   gov_whitelist_bank_send.sh --dry-run <address-or-key> [voter ...]
#
# WHY THIS EXISTS RATHER THAN testscripts/whitelist_bank_send.sh.  That one is a TEST FIXTURE: it
# hardcodes `--from treasury` and votes only through gov_vote_from_treasury.sh.  On the devnet the
# treasury holds ~99% of bonded stake, so that single vote passes anything and the design never
# shows.  On a launch chain the treasury is an ordinary funded key with NO delegations, so its vote
# lands with code 0 and contributes ZERO power -- and the proposal does not fail, it EXPIRES.  Every
# transaction along the way reports success.  Same failure this whole gov_lib family was written
# for; see the header of scripts/gov_lib.sh.
#
# WHO PAYS AND WHO VOTES ARE DIFFERENT ROLES, which is the thing the test fixture conflates:
#   --from <depositor>  needs LIQUID QDN for the deposit.  Defaults to the first voter.
#   [voter ...]         need BONDED STAKE.  Default this node's operator (config/node_params.json).
# A fee grant cannot supply the deposit -- grants pay fees, and a deposit is neither.
#
# THE BOOTSTRAP CASE IS THE HARD ONE.  When the account being whitelisted is a brand-new treasury,
# nothing has delegated to it yet, so it cannot vote for itself: whitelisting is a prerequisite for
# the account that has not yet acquired the stake that would let it vote.  One operator on a
# four-validator fleet carries 25% against a 40% quorum, so this SUBMITS and VOTES and then exits 2
# rather than blocking on a quorum this node cannot produce alone.  Exit 2 is not an error.
#
# EXIT CODES -- callers must distinguish these:
#   0  on the whitelist, verified on chain
#   2  proposal is live and voted, but needs other operators to reach quorum
#   1  something actually went wrong
#
# The proposal goes on the REGULAR track, deliberately.  Expedited is reserved by charter for
# params, upgrades and incident response; a whitelist addition is routine.  (An expedited proposal
# that misses its threshold is not rejected anyway -- x/gov/abci.go converts it to a regular one
# with the voting period measured from the ORIGINAL start, so expediting buys nothing here.)

SCRIPT_DIR="${0:A:h}"
source "$SCRIPT_DIR/../scripts/setup_env.sh" > /dev/null 2>&1
source "$SCRIPT_DIR/gov_lib.sh"

dry_run=0; force=0; reason=""; code_id=0; depositor=""
while [[ "$1" == --* ]]; do
    case "$1" in
        --dry-run)  dry_run=1; shift ;;
        --force)    force=1; shift ;;
        --reason)   reason="$2"; shift 2 ;;
        --code-id)  code_id="$2"; shift 2 ;;
        --from)     depositor="$2"; shift 2 ;;
        -h|--help)  sed -n '3,33p' "$0"; exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

target="$1"; shift 2>/dev/null
voters=("$@")
[ ${#voters[@]} -eq 0 ] && voters=(${=gov_default_voters:-$(local_operator)})
[ -n "$depositor" ] || depositor="${voters[1]}"
reason="${reason:-whitelisted by $(whoami) via gov_whitelist_bank_send.sh}"

if [ -z "$target" ]; then
    echo "Usage: gov_whitelist_bank_send.sh [--from <depositor>] [--reason TEXT] [--code-id N] <address-or-key> [voter ...]" >&2
    exit 1
fi

# Accept a keyring name or a bech32 address -- the caller may hold either.  provision_account.sh
# passes an address for an account that lives on ANOTHER machine and is not in this keyring.
if [[ "$target" == qadena1* ]]; then
    address="$target"
else
    address=$(addr_of "$target")
    [ -n "$address" ] || { echo "$target is neither a bech32 address nor a key in this keyring" >&2; exit 1 }
fi

echo "whitelisting $address (codeID $code_id)"

# IDEMPOTENT, and checked FIRST: everything after this costs a deposit and a voting period.
if qq q qadena show-scanned-contract-whitelist "$address" > /dev/null 2>&1; then
    echo "  already on the scanned-contract whitelist -- nothing to do"
    exit 0
fi

if ! require_keys "$depositor" "${voters[@]}"; then
    exit 1
fi

echo "  depositor: $depositor"
echo "  voters (on this node):"
gov_can_reach_quorum "${voters[@]}"
reachable=$?
if [ $reachable -ne 0 ] && [ $force -eq 0 ]; then
    echo
    echo "  This node cannot pass the proposal alone -- normal when several operators must vote."
    echo "  It will be submitted and voted; the others then vote on their own nodes."
fi

authority=$(qq q auth module-account gov --output json 2>/dev/null \
    | jq -r '.account.value.address // .account.base_account.address // empty')
[ -n "$authority" ] || { echo "  could not resolve the gov module address" >&2; exit 1 }

# Deposit read from the CHAIN, never hardcoded.  The test fixture's literal 100000qdn is 10x this
# chain's min_deposit and more than an unsponsored pioneer's entire balance, so an operator running
# it from their own node would fail on funds for no reason.
mindep=$(gov_param '.params.min_deposit[0].amount // empty')
[ -n "$mindep" ] || { echo "  could not read gov min_deposit" >&2; exit 1 }
echo "  deposit: ${mindep}aqdn (chain min_deposit)"

if [ $dry_run -eq 1 ]; then
    echo "  --dry-run: nothing submitted."
    exit 0
fi

gen=$(mktemp)
jq -n --arg authority "$authority" --arg address "$address" --arg reason "$reason" \
      --arg deposit "${mindep}aqdn" --argjson codeID "$code_id" '{
    messages: [ {
        "@type": "/qadena.qadena.MsgAddScannedContractWhitelist",
        authority: $authority,
        address: $address,
        codeID: $codeID,
        reason: $reason
    } ],
    metadata: "ipfs://CID",
    deposit: $deposit,
    title: "allow \($address) to take part in scanned bank sends",
    summary: $reason
}' > "$gen" || { rm -f "$gen"; exit 1 }

echo "  submitting..."
hash=$(gov_tx "submit" tx gov submit-proposal "$gen" --from "$depositor" | tail -1) || { rm -f "$gen"; exit 1 }
rm -f "$gen"
id=$(gov_proposal_id_of_tx "$hash")
[ -z "$id" ] && { echo "  could not determine the proposal id from $hash" >&2; exit 1 }
echo "  proposal id: $id"

for v in "${voters[@]}"; do
    gov_tx "vote from $v" tx gov vote "$id" yes --from "$v" > /dev/null || exit 1
done

if [ $reachable -ne 0 ]; then
    echo
    echo "  proposal $id is live and voted by ${voters[*]}."
    echo "  Ask every other operator to run, ON THEIR OWN NODE:"
    echo "      scripts/gov_vote.sh $id yes"
    echo
    echo "  Watch it with:   scripts/gov_proposal_status.sh $id"
    exit 2
fi

echo "  waiting for the proposal..."
gov_wait_proposal "$id" 420 || exit 1

# A PASSED proposal is not the same as an APPLIED one.  Without this the caller carries on and
# fails later at the first bank send, pointing at the AML ante instead of at governance.
if qq q qadena show-scanned-contract-whitelist "$address" > /dev/null 2>&1; then
    echo "  $address is on the scanned-contract whitelist"
    exit 0
fi
echo "  proposal $id passed but $address is still not on the whitelist" >&2
exit 1
