#!/bin/zsh
#
# Rebalance consensus power across the validator set, and put governance back on a REAL clock.
#
#   scripts/gov_rebalance_and_slow.sh --dry-run
#   scripts/gov_rebalance_and_slow.sh --from foundation --members foundation-m1,foundation-m2,foundation-m3
#   scripts/gov_rebalance_and_slow.sh --no-rebalance          # timings only
#   scripts/gov_rebalance_and_slow.sh --no-gov                # rebalance only
#
# WHAT THIS IS FOR.  A fleet brought up with --test-gov-timings carries a 300s/30s/300s governance
# clock, and a fleet whose treasury staked for expedited voting power carries that entire stake on
# ONE validator -- whichever `sec_veritas_before_step_1.sh --validator` picked, which defaults to
# "the largest" and is therefore decided by a tie-break nobody made deliberately.  Measured on
# qfi-mainnet 2026-09-23: pioneer2 held 85.3% of consensus power because it won that tie.
#
# Neither is fixable by re-rendering the launch config.  Genesis is written once; both of these are
# now chain STATE, changeable only by a transaction.
#
# THE TWO HALVES ARE INDEPENDENT, and it matters that you know why:
#
#   gov timings    x/gov params, changed by a governance proposal (MsgUpdateParams).
#   power balance  staking redelegations, an ordinary tx signed by the DELEGATOR.
#
# A redelegation does NOT move governance weight.  Voting power is credited to the delegator, not
# to the validator it delegated to, so moving the treasury's stake between validators leaves its
# vote exactly where it was.  What it moves is CONSENSUS power -- who proposes blocks, and who can
# halt the chain by stopping.  If you came here to change who can pass a proposal, this is the
# wrong script; that is a question about who holds stake, not about where it is pointed.
#
# ORDER IS DELIBERATE: the proposal goes FIRST, while the clock is still fast.  Slowing governance
# is the one proposal that makes every subsequent proposal slow, so doing it last would cost six
# hours on anything that followed.  If the chain is ALREADY slow this script says so and the
# proposal simply takes its real time.
#
# RUN IT ON A NODE.  Like every script in the gov_* family it addresses qadenad at the DEFAULT
# endpoint and reads $QADENAHOME/config/node_params.json to learn which pioneer this box is, so it
# expects to run on an operator's own machine rather than against a remote RPC.  The keys it signs
# with must be in THAT box's keyring: a redelegation is signed by the delegator, and operating a
# validator does not put anyone else's key on your host.
#
# WHAT IT REFUSES TO PRETEND.  With n validators, someone necessarily holds >= 1/n, and block
# production needs > 2/3 online -- so below FOUR validators there is no distribution that survives
# losing one.  On a two-validator chain an even split is strictly WORSE for liveness than a lopsided
# one: at 50/50 either node stopping halts the chain, while at 85/15 the big one alone can carry it.
# This script says that out loud rather than quietly making the number prettier.

SCRIPT_DIR="${0:A:h}"
# CAPTURED AT TOP LEVEL.  In zsh $0 inside a function is the FUNCTION'S name, not the script's
# (FUNCTION_ARGZERO is on by default), so `sed -n ... "$0"` in usage() read a file called "usage"
# and printed `sed: usage: No such file or directory` instead of the header.
SELF="${0:A}"
source "$SCRIPT_DIR/../scripts/setup_env.sh" > /dev/null 2>&1
source "$SCRIPT_DIR/gov_lib.sh"

set -u

# The "slow" values.  Cosmos duration strings.  Defaults are the launch-config's real clock, NOT
# the SDK defaults -- this script exists to restore what a test render overwrote.
SLOW_VOTING="72h0m0s"
SLOW_EXPEDITED="6h0m0s"
SLOW_DEPOSIT="24h0m0s"

DRY=0; DO_GOV=1; DO_BAL=1; FROM=""; MEMBERS=""; MAX_PCT=""; DEPOSITOR=""; WANT_CHAIN=""
NODE=""; KEYHOME=""; KEYPASS=""
VOTERS=()

usage() {
    sed -n '3,12p' "$SELF"
    print -r -- ""
    print -r -- "  --dry-run              print the plan and the exact commands; change nothing"
    print -r -- "  --only gov|rebalance|both"
    print -r -- "                         do just one half.  'gov' sets the slow timings and"
    print -r -- "                         touches no stake; 'rebalance' moves stake and leaves"
    print -r -- "                         governance alone.  Default both."
    print -r -- "                         --gov-only / --rebalance-only are the same thing;"
    print -r -- "                         --no-gov / --no-rebalance are the older spellings."
    print -r -- "  --from <key>           delegator whose stake is moved.  Default: the largest"
    print -r -- "                         delegator this keyring can sign for."
    print -r -- "  --members <a,b,c>      member key names, when --from is a MULTISIG bucket."
    print -r -- "                         Without it, a multisig delegator only PRINTS its ceremony."
    print -r -- "  --max-pct <n>          cap any one validator at n% of bonded stake."
    print -r -- "                         Default: an even split across the bonded set."
    print -r -- "  --deposit-from <key>   who pays the proposal deposit (needs LIQUID qdn; a fee"
    print -r -- "                         grant cannot supply a deposit).  Default: first voter."
    print -r -- "  --voting-period <d>    default $SLOW_VOTING"
    print -r -- "  --expedited-period <d> default $SLOW_EXPEDITED"
    print -r -- "  --deposit-period <d>   default $SLOW_DEPOSIT"
    print -r -- "  [voter ...]            accounts that vote.  Default: this node's operator."
    print -r -- "  --node <rpc>           the chain RPC, when it is NOT on this box."
    print -r -- "  --chain-id <id>        REFUSE to run unless the node reports this chain-id."
    print -r -- "                         Use it whenever a devnet may be running locally."
    print -r -- "  --keyring-home <dir>   keyring holding the signing keys (e.g. the coordinator"
    print -r -- "                         keyring ~/qadena-launch/fleet-launch/coord).  Implies --keyring-backend file."
    print -r -- "  --keyring-passfile <f> passphrase for that keyring, first line."
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)          DRY=1; shift ;;
        # POSITIVE FORM, because the negative one reads backwards: "just rebalance" spelled
        # --no-gov makes you invert the thing you actually want before you can type it.  The
        # --no-* flags stay as aliases -- they are in the runbooks already.
        --only)
            case "$2" in
                gov|timings|slow)   DO_GOV=1; DO_BAL=0 ;;
                rebalance|balance)  DO_GOV=0; DO_BAL=1 ;;
                both|all)           DO_GOV=1; DO_BAL=1 ;;
                # `print -u2 --`: the message STARTS with "--only", which print parses as its
                # own flags without the -- terminator ("bad option: -y" from the 'only').
                *) print -u2 -- "--only takes gov, rebalance or both (got '$2')"; exit 1 ;;
            esac
            shift 2 ;;
        --gov-only)         DO_GOV=1; DO_BAL=0; shift ;;
        --rebalance-only)   DO_GOV=0; DO_BAL=1; shift ;;
        --no-gov)           DO_GOV=0; shift ;;
        --no-rebalance)     DO_BAL=0; shift ;;
        --from)             FROM="$2"; shift 2 ;;
        --members)          MEMBERS="$2"; shift 2 ;;
        --max-pct)          MAX_PCT="$2"; shift 2 ;;
        --deposit-from)     DEPOSITOR="$2"; shift 2 ;;
        --node)             NODE="$2"; shift 2 ;;
        --chain-id)         WANT_CHAIN="$2"; shift 2 ;;
        --keyring-home)     KEYHOME="$2"; shift 2 ;;
        --keyring-passfile) KEYPASS=$(head -1 "$2"); shift 2 ;;
        --voting-period)    SLOW_VOTING="$2"; shift 2 ;;
        --expedited-period) SLOW_EXPEDITED="$2"; shift 2 ;;
        --deposit-period)   SLOW_DEPOSIT="$2"; shift 2 ;;
        -h|--help)          usage; exit 0 ;;
        --*)                print -u2 "unknown option: $1"; usage >&2; exit 1 ;;
        *)                  VOTERS+=("$1"); shift ;;
    esac
done

# local_operator() reads $QADENAHOME/config/node_params.json, which only exists ON a node.  Run
# from a workstation there is no sensible default voter, and an empty one would surface much later
# as "NO SUCH KEY in this keyring" against an empty name.
# BOTH HALVES OFF IS NOT A NO-OP WORTH HONOURING.  With DO_GOV=0 and DO_BAL=0 the script printed
# the state report and exited 0, which reads exactly like a successful run that decided nothing
# needed doing.  Two negative flags that cancel out is a typo, not an instruction.
if (( ! DO_GOV && ! DO_BAL )); then
    print -u2 "nothing to do: both halves are switched off."
    print -u2 "  --only gov        just the timings"
    print -u2 "  --only rebalance  just the stake"
    exit 1
fi

SEQOFF=0
# --from IS THE ANSWER FOR BOTH HALVES when only one account matters.  Without this, `--only gov
# --from foundation` fell back to local_operator(), which reads $QADENAHOME/config/node_params.json
# -- on a workstation that is the LOCAL DEVNET's identity, so it named a pioneer that exists on a
# different chain entirely and reported "NO SUCH KEY in this keyring".
(( ${#VOTERS} )) || [[ -z "$FROM" ]] || VOTERS=("$FROM")
(( ${#VOTERS} )) || VOTERS=(${=gov_default_voters:-$(local_operator)})
if (( DO_GOV )) && [[ -z "${VOTERS[1]:-}" ]]; then
    print -u2 "no voter given and this box is not a node (no config/node_params.json)."
    print -u2 "  Name the accounts that hold bonded stake, e.g.:  $SELF ... foundation"
    exit 1
fi
[[ -n "$DEPOSITOR" ]] || DEPOSITOR="${VOTERS[1]}"

# NODE AND KEYS NEED NOT BE ON THE SAME BOX, and on a test fleet they are not: the chain runs on
# the primary while the coordinator keyring -- which holds the treasury, i.e. the only delegator
# with enough stake to matter -- lives on the workstation that drove the bring-up.  gov_lib's qq
# assumes an operator's own node, where both are local.  Overriding it HERE keeps one definition of
# how qadenad is invoked while letting the two live apart.
#
# --node GOES ONLY ON query/tx/status.  The `keys` subcommands do not register that flag and cobra
# errors on an unknown one, so appending it unconditionally breaks every key lookup -- which is
# exactly why gov_lib's qq has no --node to begin with.
if [[ -n "$NODE" || -n "$KEYHOME" ]]; then
    # WHICH FLAG GOES ON WHICH SUBCOMMAND -- and they are NOT interchangeable:
    #
    #   --home              root persistent flag, valid everywhere, so it goes BEFORE the
    #                       subcommand.  Keyring work points it at KEYHOME; everything else must
    #                       keep the NODE home, or a query resolves against a keyring directory.
    #   --keyring-backend   registered on `keys` and `tx` ONLY.  `qadenad status --keyring-backend
    #                       file` answers "unknown flag: --keyring-backend" -- measured, and it is
    #                       what made the first version of this fail as "could not reach a node",
    #                       blaming the network for a flag error.
    #   --node              registered on query/tx/status, NOT at the root, so it goes AFTER the
    #                       subcommand.
    #
    # Hence two arrays rather than one: what is legal before the verb, and what is legal after it.
    qq() {
        local -a _pre _post
        _pre=(--home "$QADENAHOME"); _post=()
        case "$1" in
            keys|tx) [[ -n "$KEYHOME" ]] && { _pre=(--home "$KEYHOME"); _post+=(--keyring-backend file) } ;;
        esac
        if [[ -n "$NODE" ]]; then
            case "$1" in (q|query|tx|status) _post+=(--node "$NODE") ;; esac
        fi
        if [[ -n "$KEYPASS" ]]; then
            { print -r -- "$KEYPASS"; print -r -- "$KEYPASS" } \
                | "$qadenabin/qadenad" "${_pre[@]}" "$@" "${_post[@]}"
        else
            "$qadenabin/qadenad" "${_pre[@]}" "$@" "${_post[@]}"
        fi
    }
fi

# multisig_sign.sh TAKES ITS KEYRING FROM THE ENVIRONMENT, not from flags -- QADENAHOME,
# QADENA_KEYRING_BACKEND and QADENA_KEYRING_PASS, the same way sec_veritas_before_step_1.sh points
# it at the coordinator keyring.  Set per call rather than exported, because QADENAHOME here is the
# NODE home and overwriting it globally would send every query at a keyring directory.
# ALL FOUR, because multisig_sign.sh reads every one of them from the environment and its
# defaults are wrong for a remote chain:
#
#   QADENAHOME            its --home; must be the KEYRING, not the node home
#   QADENA_KEYRING_*      backend and passphrase for that keyring
#   QADENA_NODE           DEFAULTS TO tcp://localhost:26657 (multisig_sign.sh:40).  Unset, it read
#                         account number and sequence from whatever is on localhost -- here a
#                         devnet -- and answered "account qadena15pk5p... not found: key not
#                         found" for an account that exists perfectly well on the fleet.
#   QADENA_CHAIN_ID       required for EVERY subcommand, not just sign (multisig_sign.sh:185),
#                         so broadcast died on "--chain-id is required" after the signing worked.
#
# Set per call rather than exported: QADENAHOME here is the NODE home, and exporting the keyring
# path over it would point every query in this script at a keyring directory.
# AN ARRAY, NOT ${NODE:+--node "$NODE"}.
#
# zsh does not word-split an unquoted parameter expansion, so that form reaches the callee as ONE
# argument -- the literal string `--node tcp://10.211.55.5:26657` -- and multisig_sign.sh answers
# "unknown option: --node tcp://10.211.55.5:26657", which reads like an unsupported flag rather
# than a quoting bug.  veritas_full_setup.sh carries a comment about this exact trap, measured on
# its own --pool argument; this is the same mistake made again three files away.
NODE_ARG=(); [[ -n "$NODE" ]] && NODE_ARG=(--node "$NODE")

msig() {
    QADENAHOME="${KEYHOME:-$QADENAHOME}" \
    QADENA_KEYRING_BACKEND=file \
    QADENA_KEYRING_PASS="$KEYPASS" \
    QADENA_NODE="${NODE:-${QADENA_NODE:-tcp://localhost:26657}}" \
    QADENA_CHAIN_ID="$CHAIN" \
        "$SCRIPT_DIR/multisig_sign.sh" "$@"
}

# ONE CEREMONY FOR BOTH HALVES.  The rebalance grew its own sign/combine/broadcast loop and the
# gov half had none at all, which is how `--only gov` reached a treasury it could not sign with.
# Returns the TXHASH on stdout so a caller can resolve a proposal id; all progress goes to stderr.
#
# SEQOFF advances per ceremony: several txs from one bucket in a single run are all signed against
# the same on-chain sequence, because none of them has landed yet, and combine reads the SHARES'
# sequence rather than the chain's.
ceremony() {
    local label="$1" unsigned="$2" bucket="$3" members="$4"
    local -a mem shares soff; mem=(${(s:,:)members}); shares=(); soff=()
    local i=1 m out rc=0
    (( SEQOFF > 0 )) && soff=(--sequence-offset "$SEQOFF")
    for m in $mem; do
        run msig sign --tx "$unsigned" --multisig "$bucket" --from "$m" \
            --chain-id "$CHAIN" "${NODE_ARG[@]}" "${soff[@]}" \
            --out "${unsigned:r}.s${i}.json" >&2 || return 1
        shares+=("${unsigned:r}.s${i}.json"); i=$(( i + 1 ))
    done
    run msig combine --tx "$unsigned" --multisig "$bucket" --chain-id "$CHAIN" \
        "${NODE_ARG[@]}" --out "${unsigned:r}.signed.json" "${shares[@]}" >&2 || return 1
    if (( DRY )); then
        print -r -- "    + msig broadcast --tx ${unsigned:r}.signed.json --chain-id $CHAIN ${NODE_ARG[*]}" >&2
        SEQOFF=$(( SEQOFF + 1 )); return 0
    fi
    # rc 2 is "accepted, not yet in a block" -- NOT a failure.  Treating it as one is what makes an
    # operator re-send a transaction that is about to land.
    out=$(msig broadcast --tx "${unsigned:r}.signed.json" --chain-id "$CHAIN" "${NODE_ARG[@]}" 2>&1) || rc=$?
    print -r -- "$out" >&2
    SEQOFF=$(( SEQOFF + 1 ))
    (( rc == 0 || rc == 2 )) || { print -u2 "  $label: FAILED"; return 1 }
    print -r -- "$out" | grep -oE '\b[0-9A-F]{64}\b' | head -1
}

# .type is the only reliable multisig marker -- see the note at the redelegation below.
is_multi() { [[ "$(qq keys show "$1" --output json 2>/dev/null | jq -r '.type // empty')" == "multi" ]] }

run() {   # echo-or-execute, so --dry-run shows exactly what would happen
    if (( DRY )); then print -r -- "    + $*"; return 0; fi
    "$@"
}

# ==============================================================================================
# 0. STATE
# ==============================================================================================
print -r -- "==== current state ===================================================="

# WHICH CHAIN, SAID OUT LOUD, BEFORE ANY NUMBERS.
#
# Without --node this addresses localhost:26657, and a workstation that has ever run the devnet
# still has one there.  Measured 2026-09-24: run from the Mac with no --node, this reported a
# complete and internally consistent picture of qadena_4828-1 -- a local devnet at height 142518 --
# while the operator believed they were looking at the M1-M2 fleet.  Nothing about that output
# said otherwise.  A rebalance aimed at the wrong chain moves real stake on it.
# STDERR IS KEPT, NOT DISCARDED.  `2>/dev/null` here is what turned "unknown flag:
# --keyring-backend" into "could not reach a node" -- a flag bug reported as a network one, which
# is the same trap sec_veritas_before_step_1.sh falls into at its own chain-id derivation.
_st=$(qq status 2>&1)
CHAIN=$(print -r -- "$_st" | jq -r '.node_info.network // empty' 2>/dev/null)
if [[ -z "$CHAIN" ]]; then
    print -u2 "could not read the chain-id from ${NODE:-tcp://localhost:26657}"
    print -r -- "$_st" | tail -3 | sed 's/^/    /' >&2
    exit 1
fi
print -r -- "  node      ${NODE:-tcp://localhost:26657}"
print -r -- "  chain-id  $CHAIN"
if [[ -n "$WANT_CHAIN" && "$CHAIN" != "$WANT_CHAIN" ]]; then
    print -u2 ""
    print -u2 "REFUSING: this node reports '$CHAIN', not '$WANT_CHAIN'."
    print -u2 "  Pass --node for the chain you mean.  A devnet on localhost answers just as"
    print -u2 "  convincingly as the fleet does."
    exit 1
fi
print -r -- ""

TOTAL=$(bonded_total)
[[ -n "$TOTAL" && "$TOTAL" != "0" ]] || { print -u2 "could not read bonded stake -- is the node reachable?"; exit 1 }

# One query, reused: validators sorted by tokens descending.
VJSON=$(qq q staking validators --output json 2>/dev/null \
        | jq -c '[.validators[] | select(.status=="BOND_STATUS_BONDED")
                  | {op: .operator_address, moniker: .description.moniker, tokens: .tokens}]
                 | sort_by(.tokens | tonumber) | reverse')
NVAL=$(print -r -- "$VJSON" | jq 'length')

printf "  %-22s %-46s %14s %8s\n" moniker operator qdn share
print -r -- "$VJSON" | jq -r '.[] | [.moniker, .op, .tokens] | @tsv' | while IFS=$'\t' read -r mon op tok; do
    printf "  %-22s %-46s %14s %7s%%\n" "$mon" "$op" "$(echo "$tok / 1000000000000000000" | bc)" "$(pct "$tok" "$TOTAL")"
done
print -r -- ""
print -r -- "  $NVAL bonded validator(s), total $(echo "$TOTAL / 1000000000000000000" | bc) QDN"

# LIVENESS, STATED PLAINLY.  Block production needs > 2/3 of bonded power online, so a validator
# holding >= 1/3 can halt the chain by stopping.  Below four validators that is unavoidable, and
# rebalancing cannot fix it -- saying so here is the difference between a useful number and a
# reassuring one.
print -r -- ""
print -r -- "  liveness: a validator at >= 33.34% can halt the chain by stopping."
print -r -- "$VJSON" | jq -r '.[] | [.moniker, .tokens] | @tsv' | while IFS=$'\t' read -r mon tok; do
    _rest=$(echo "$TOTAL - $tok" | bc)
    if [[ "$(echo "$(pct "$_rest" "$TOTAL") < 66.67" | bc)" == "1" ]]; then
        printf "    %-22s if it stops, %s%% remains -- CHAIN HALTS\n" "$mon" "$(pct "$_rest" "$TOTAL")"
    else
        printf "    %-22s if it stops, %s%% remains -- chain continues\n" "$mon" "$(pct "$_rest" "$TOTAL")"
    fi
done
if (( NVAL < 4 )); then
    print -r -- ""
    print -r -- "  !! $NVAL validator(s).  Below FOUR, no distribution survives losing one: someone"
    print -r -- "     necessarily holds >= 1/$NVAL and production needs > 2/3 online."
    if (( NVAL == 1 )); then
        print -r -- "     With ONE there is nothing to rebalance -- it holds everything by definition."
    elif (( NVAL == 2 )); then
        print -r -- "     At two, an EVEN split is WORSE than a lopsided one: 50/50 halts on either"
        print -r -- "     loss, while 85/15 lets the large one carry the chain alone."
    fi
    print -r -- "     Rebalancing changes WHICH node is the single point of failure, not whether"
    print -r -- "     there is one.  Adding validators is the only thing that does."
fi

# ==============================================================================================
# 1. GOVERNANCE TIMINGS  (first, while the clock may still be fast)
# ==============================================================================================
if (( DO_GOV )); then
    print -r -- ""
    print -r -- "==== 1. governance timings ==========================================="

    CUR_VOTING=$(gov_param '.params.voting_period')
    CUR_EXP=$(gov_param '.params.expedited_voting_period')
    CUR_DEP=$(gov_param '.params.max_deposit_period')
    print -r -- "  now:    voting $CUR_VOTING   expedited $CUR_EXP   deposit $CUR_DEP"
    print -r -- "  target: voting $SLOW_VOTING   expedited $SLOW_EXPEDITED   deposit $SLOW_DEPOSIT"

    if [[ "$CUR_VOTING" == "$SLOW_VOTING" && "$CUR_EXP" == "$SLOW_EXPEDITED" && "$CUR_DEP" == "$SLOW_DEPOSIT" ]]; then
        print -r -- "  already on the target clock -- nothing to propose"
    else
        # THIS PROPOSAL RUNS ON THE CURRENT CLOCK, not the target one.  Fast now means it lands in
        # ~30s; if the chain is already slow, expect the real expedited period.
        print -r -- "  this proposal is decided on the CURRENT clock (expedited $CUR_EXP)"

        # MsgUpdateParams REPLACES THE WHOLE PARAMS STRUCT.  Sending only the three durations
        # would reset quorum, threshold, veto, min_deposit and the rest to the zero value -- a
        # governance wipe dressed up as a timing change.  So: read what is there, change three
        # fields, send it all back.
        AUTH=$(qq q auth module-account gov --output json 2>/dev/null \
                | jq -r '.account.value.address // .account.base_account.address // .account.address // empty')
        [[ -n "$AUTH" ]] || { print -u2 "  could not resolve the gov module authority address"; exit 1 }

        PARAMS=$(qq q gov params --output json 2>/dev/null | jq -c '.params')
        [[ -n "$PARAMS" && "$PARAMS" != "null" ]] || { print -u2 "  could not read gov params"; exit 1 }
        NEWP=$(print -r -- "$PARAMS" | jq -c \
                 --arg v "$SLOW_VOTING" --arg e "$SLOW_EXPEDITED" --arg d "$SLOW_DEPOSIT" \
                 '.voting_period=$v | .expedited_voting_period=$e | .max_deposit_period=$d')

        # The deposit must clear min_deposit or the proposal sits in DEPOSIT_PERIOD and expires.
        MIND=$(print -r -- "$PARAMS" | jq -r '.min_deposit[0] | .amount + .denom')

        PFILE="${${TMPDIR:-/tmp}%/}/gov-slow-timings.$$.json"
        jq -n --arg auth "$AUTH" --argjson p "$NEWP" --arg dep "$MIND" \
           '{messages:[{"@type":"/cosmos.gov.v1.MsgUpdateParams", authority:$auth, params:$p}],
             metadata:"", deposit:$dep,
             title:"Restore real governance timings",
             summary:"Set voting_period, expedited_voting_period and max_deposit_period to their launch values. All other gov params are carried over unchanged."}' \
           > "$PFILE"
        print -r -- "  proposal: $PFILE  (deposit $MIND)"
        (( DRY )) && { print -r -- "    + qadenad tx gov submit-proposal $PFILE --from $DEPOSITOR"; jq -r '.messages[0].params | {voting_period, expedited_voting_period, max_deposit_period}' "$PFILE" | sed 's/^/    /' }

        # CHECK REACHABILITY BEFORE SUBMITTING.  A proposal that cannot reach quorum does not
        # fail, it EXPIRES -- and every transaction along the way reports success.
        print -r -- "  voting power check:"
        if ! gov_can_reach_quorum "${VOTERS[@]}"; then
            print -u2 "  these voters cannot reach quorum alone."
            print -u2 "  Name the accounts that hold bonded stake, e.g. the treasury, as arguments."
            (( DRY )) || exit 1
        fi

        if (( ! DRY )); then
            fee_granter=$(gov_discover_fee_granter "$(addr_of "$DEPOSITOR")")
            if is_multi "$DEPOSITOR"; then
                [[ -n "$MEMBERS" ]] || { print -u2 "  $DEPOSITOR is a multisig -- pass --members"; exit 1 }
                _u="${${TMPDIR:-/tmp}%/}/gov-submit.$$.json"
                run msig build-submit-proposal --from "$DEPOSITOR" --proposal-file "$PFILE" \
                    --chain-id "$CHAIN" "${NODE_ARG[@]}" --out "$_u" || exit 1
                hash=$(ceremony "submit slow-timings proposal" "$_u" "$DEPOSITOR" "$MEMBERS") || exit 1
            else
                hash=$(gov_tx "submit slow-timings proposal" tx gov submit-proposal "$PFILE" --from "$DEPOSITOR") || exit 1
            fi
            PID=$(gov_proposal_id_of_tx "$hash")
            [[ -n "$PID" ]] || { print -u2 "  submitted ($hash) but could not read the proposal id"; exit 1 }
            print -r -- "  proposal id $PID"
            for v in "${VOTERS[@]}"; do
                fee_granter=$(gov_discover_fee_granter "$(addr_of "$v")")
                if is_multi "$v"; then
                    [[ -n "$MEMBERS" ]] || { print -u2 "  $v is a multisig -- pass --members"; exit 1 }
                    _u="${${TMPDIR:-/tmp}%/}/gov-vote-$v.$$.json"
                    run msig build-vote --from "$v" --proposal "$PID" --vote yes \
                        --chain-id "$CHAIN" "${NODE_ARG[@]}" --out "$_u" || exit 1
                    ceremony "vote yes as $v" "$_u" "$v" "$MEMBERS" > /dev/null || exit 1
                else
                    gov_tx "vote yes as $v" tx gov vote "$PID" yes --from "$v" > /dev/null || exit 1
                fi
            done
            # Wait on the CURRENT clock plus slack, not the target one.
            gov_wait_proposal "$PID" 900 || exit 1
            print -r -- "  timings now: voting $(gov_param '.params.voting_period')  expedited $(gov_param '.params.expedited_voting_period')"
        fi
    fi
fi

# ==============================================================================================
# 2. REBALANCE
# ==============================================================================================
if (( DO_BAL )); then
    print -r -- ""
    print -r -- "==== 2. rebalance consensus power ===================================="

    if (( NVAL < 2 )); then
        print -r -- "  $NVAL validator -- nothing to rebalance"
        exit 0
    fi

    # TARGET.  Even split unless --max-pct caps it.  Integer aqdn throughout: these are 1e18-scaled
    # and bc's default scale=0 truncates, which is the safe direction for a cap.
    if [[ -n "$MAX_PCT" ]]; then
        TARGET=$(echo "$TOTAL * $MAX_PCT / 100" | bc)
        print -r -- "  target: no validator above $MAX_PCT% ($(echo "$TARGET / 1000000000000000000" | bc) QDN)"
    else
        TARGET=$(echo "$TOTAL / $NVAL" | bc)
        print -r -- "  target: even split, $(echo "$TARGET / 1000000000000000000" | bc) QDN each"
    fi

    # jq CANNOT DO THIS ARITHMETIC, AND FAILS BY PRINTING SOMETHING PLAUSIBLE.
    #
    # jq numbers are IEEE 754 doubles: exact only to ~9e15.  These are aqdn, 1e18-scaled, so
    # 58000000000000000000000 does not survive `tonumber` -- it came back as 2.4e+22, which bc
    # rejects ("bad character '+'") and qadenad rejects ("invalid decimal coin expression:
    # 2.4e+22aqdn").  The same loss made the excess read 23999 QDN instead of 24000.  Measured on
    # M1-M2 2026-09-24.
    #
    # So NO AMOUNT EVER PASSES THROUGH jq ARITHMETIC.  jq extracts .tokens, which is already a
    # STRING of exact digits in the cosmos JSON, and every comparison and subtraction is done in
    # bc, which is arbitrary-precision.  jq's sort_by(tonumber) above is left alone deliberately:
    # it decides processing ORDER only, where a near-tie misordering changes nothing.
    OVER_ROWS=(); UNDER_ROWS=()
    for _r in ${(f)"$(print -r -- "$VJSON" | jq -r '.[] | [.op, .moniker, .tokens] | @tsv')"}; do
        _op="${_r%%$'\t'*}"; _rr="${_r#*$'\t'}"
        _mon="${_rr%%$'\t'*}"; _tok="${_rr#*$'\t'}"
        if [[ "$(echo "$_tok > $TARGET" | bc)" == "1" ]]; then
            OVER_ROWS+=("$_op"$'\t'"$_mon"$'\t'"$(echo "$_tok - $TARGET" | bc)")
        elif [[ "$(echo "$_tok < $TARGET" | bc)" == "1" ]]; then
            UNDER_ROWS+=("$_op"$'\t'"$_mon"$'\t'"$(echo "$TARGET - $_tok" | bc)")
        fi
    done

    if (( ${#OVER_ROWS} == 0 )); then
        print -r -- "  already within target -- nothing to move"
        exit 0
    fi

    # FIELD 2, not the whole row: these are op<TAB>moniker<TAB>amount, and printing the lot put a
    # bech32 operator address and a raw 1e18 amount on a line meant to read as a summary.
    _on=(); for _r in $OVER_ROWS;  do _t="${_r#*$'\t'}"; _on+=("${_t%%$'\t'*}"); done
    _un=(); for _r in $UNDER_ROWS; do _t="${_r#*$'\t'}"; _un+=("${_t%%$'\t'*}"); done
    print -r -- "  over:  ${(j:, :)_on}"
    print -r -- "  under: ${(j:, :)_un}"
    print -r -- ""

    # ARRAYS, NOT `| while`.  zsh runs the right-hand side of a pipeline in a SUBSHELL, so a
    # `jq ... | while read` loop cannot keep state: REM's decrements and SEQOFF's increments were
    # both lost at the end of each iteration.  That is not cosmetic -- with REM reset every time,
    # each under-weighted validator received the FULL move instead of its share, so a rebalance
    # would over-redelegate by a factor of however many validators were under target.  ${(f)...}
    # splits on newlines into an array and the for-loop runs in THIS shell.
    #
    # SEQOFF: several redelegations from one multisig bucket in a single run are all signed against
    # the same on-chain sequence, because none of them has landed yet.  combine reads the SHARES'
    # sequence, not the chain's, so the second tx onward must say how far ahead it is.
    for _row in $OVER_ROWS; do
        sop="${_row%%$'\t'*}"; _rest="${_row#*$'\t'}"
        smon="${_rest%%$'\t'*}"; sexc="${_rest#*$'\t'}"
        print -r -- "  $smon: $(echo "$sexc / 1000000000000000000" | bc) QDN above target"

        DELEGS=$(qq q staking delegations-to "$sop" --output json 2>/dev/null \
                 | jq -c '[.delegation_responses[] | {addr: .delegation.delegator_address, amt: .balance.amount}]
                          | sort_by(.amt | tonumber) | reverse')

        # --from names the delegator explicitly; otherwise take the largest whose key we hold.
        PICK=""; PICKADDR=""
        if [[ -n "$FROM" ]]; then
            PICKADDR=$(addr_of "$FROM"); PICK="$FROM"
            [[ -n "$PICKADDR" ]] || { print -u2 "    --from $FROM is not a key in this keyring"; exit 1 }
            if ! print -r -- "$DELEGS" | jq -e --arg a "$PICKADDR" 'map(select(.addr==$a)) | length > 0' > /dev/null; then
                print -u2 "    $FROM has no delegation to $smon -- nothing of its to move"
                continue
            fi
        else
            KEYNAMES=(${(f)"$(list_keys)"})
            for _d in ${(f)"$(print -r -- "$DELEGS" | jq -r '.[] | .addr')"}; do
                for k in $KEYNAMES; do
                    if [[ "$(addr_of "$k")" == "$_d" ]]; then PICK="$k"; PICKADDR="$_d"; break; fi
                done
                [[ -n "$PICK" ]] && break
            done
            [[ -n "$PICK" ]] || { print -u2 "    no delegator to $smon has a key in this keyring -- pass --from"; continue }
        fi

        HELD=$(print -r -- "$DELEGS" | jq -r --arg a "$PICKADDR" '.[] | select(.addr==$a) | .amt')
        MOVE="$sexc"; [[ "$(echo "$HELD < $MOVE" | bc)" == "1" ]] && MOVE="$HELD"
        print -r -- "    delegator $PICK holds $(echo "$HELD / 1000000000000000000" | bc) QDN here; moving $(echo "$MOVE / 1000000000000000000" | bc) QDN"

        # MULTISIG OR NOT.  A bucket has a threshold; an ordinary key does not.  Getting this wrong
        # is not subtle -- `tx ... --from <multisig>` fails as though the tx were unsigned rather
        # than starting a ceremony.
        # .type, NOT .threshold.  `keys show --output json` returns
        #     {name, type, address, pubkey}
        # with NO top-level threshold -- it lives inside .pubkey, which is itself a JSON STRING.
        # Testing `.threshold // empty` therefore came back empty for a 3-of-5 bucket, the script
        # took the single-signature path, and qadenad answered "cannot sign with offline keys".
        # Measured on M1-M2 2026-09-24 with --members supplied and ignored.
        _kj=$(qq keys show "$PICK" --output json 2>/dev/null)
        THR=""
        if [[ "$(print -r -- "$_kj" | jq -r '.type // empty')" == "multi" ]]; then
            THR=$(print -r -- "$_kj" | jq -r '(.pubkey | fromjson).threshold // "N"' 2>/dev/null)
            : ${THR:=N}
        fi

        # Spread the move across the under-weighted validators, neediest first.
        REM="$MOVE"
        for _urow in $UNDER_ROWS; do
            [[ "$(echo "$REM <= 0" | bc)" == "1" ]] && continue
            dop="${_urow%%$'\t'*}"; _urest="${_urow#*$'\t'}"
            dmon="${_urest%%$'\t'*}"; ddef="${_urest#*$'\t'}"
            AMT="$ddef"; [[ "$(echo "$REM < $AMT" | bc)" == "1" ]] && AMT="$REM"
            [[ "$(echo "$AMT <= 0" | bc)" == "1" ]] && continue
            print -r -- "    -> $dmon: $(echo "$AMT / 1000000000000000000" | bc) QDN"

            if [[ -n "$THR" ]]; then
                # ${...%/} -- macOS sets TMPDIR WITH a trailing slash, so the obvious form
                # produced /var/folders/.../T//redelegate-... : harmless, but it appears in every
                # printed ceremony command an operator copies by hand.
                UNS="${${TMPDIR:-/tmp}%/}/redelegate-${smon}-${dmon}.$$.json"
                if [[ -z "$MEMBERS" ]]; then
                    print -r -- "      $PICK is a ${THR}-of-N multisig and no --members was given."
                    print -r -- "      Run the ceremony where the member keys are:"
                    print -r -- "        scripts/multisig_sign.sh build-redelegate --from $PICK \\"
                    print -r -- "            --src-validator $sop --validator $dop --amount ${AMT}aqdn \\"
                    print -r -- "            --chain-id $CHAIN${NODE:+ --node $NODE} --out $UNS"
                    print -r -- "        scripts/multisig_sign.sh sign --tx $UNS --multisig $PICK --from <member> \\"
                    print -r -- "            --chain-id $CHAIN${NODE:+ --node $NODE} ${SEQOFF:+--sequence-offset $SEQOFF }--out <share>"
                    print -r -- "        scripts/multisig_sign.sh combine --tx $UNS --multisig $PICK \\"
                    print -r -- "            --chain-id $CHAIN${NODE:+ --node $NODE} --out ${UNS:r}.signed.json <share>..."
                    print -r -- "        scripts/multisig_sign.sh broadcast --tx ${UNS:r}.signed.json \\"
                    print -r -- "            --chain-id $CHAIN${NODE:+ --node $NODE}"
                else
                    # BUILD THROUGH multisig_sign.sh, not by hand.
                    #
                    # This used `tx staking redelegate --generate-only` directly, which produces a
                    # tx with NO FEE -- and CheckTx rejected it with code 13, "gas prices too low,
                    # got: 0aqdn required: 7aqdn", AFTER all three members had signed.  Every
                    # build-* in multisig_sign.sh applies $GAS/$GAS_PRICES precisely so that the
                    # fee is not something each caller has to remember; build-redelegate was the
                    # one that did not exist yet, so this rolled its own and lost that.
                    run msig build-redelegate --from "$PICK" \
                        --src-validator "$sop" --validator "$dop" --amount "${AMT}aqdn" \
                        --chain-id "$CHAIN" "${NODE_ARG[@]}" --out "$UNS"
                    # ONE COPY OF THE CEREMONY.  This was an inline sign/combine/broadcast loop
                    # identical to ceremony() above -- a second copy in the same file, which is the
                    # smaller version of the problem that made this script rediscover the keyring
                    # env, the chain-id, the node and the arg-splitting one broadcast at a time.
                    # ceremony() also advances SEQOFF itself, so the bump that stood here is gone.
                    ceremony "redelegate $smon -> $dmon" "$UNS" "$PICK" "$MEMBERS" > /dev/null \
                        || print -u2 "    skipped $smon -> $dmon (see the error above)"
                fi
            else
                if (( DRY )); then
                    print -r -- "    + qadenad tx staking redelegate $sop $dop ${AMT}aqdn --from $PICK"
                else
                    fee_granter=$(gov_discover_fee_granter "$PICKADDR")
                    # CARRY ON, BUT DO NOT INVENT A REASON.  A refusal here is commonly an active
                    # redelegation entry (the chain blocks a second hop for the unbonding period),
                    # but it can equally be a malformed amount or an unfunded delegator -- and
                    # gov_tx has ALREADY printed the chain's own message.  Naming a likely cause on
                    # top of it sent the last operator looking for a redelegation entry that did
                    # not exist, when the real error two lines up said "invalid decimal coin
                    # expression".  Say what was skipped; let the printed error say why.
                    gov_tx "redelegate $smon -> $dmon" tx staking redelegate "$sop" "$dop" "${AMT}aqdn" \
                        --from "$PICK" > /dev/null \
                        || print -u2 "    skipped $smon -> $dmon (see the error above)"
                fi
            fi
            REM=$(echo "$REM - $AMT" | bc)
        done
    done

    if (( ! DRY )); then
        print -r -- ""
        print -r -- "  resulting distribution:"
        T2=$(bonded_total)
        qq q staking validators --output json 2>/dev/null \
          | jq -r '.validators[] | select(.status=="BOND_STATUS_BONDED") | [.description.moniker, .tokens] | @tsv' \
          | while IFS=$'\t' read -r mon tok; do
                printf "    %-22s %7s%%\n" "$mon" "$(pct "$tok" "$T2")"
            done
    fi
fi

print -r -- ""
print -r -- "done."
