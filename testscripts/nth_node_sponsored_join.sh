#!/bin/zsh
#
# nth_node_bringup, for a joiner sponsored by a bucket MULTISIG -- test fleets only.
#
#   nth_node_sponsored_join.sh --primary <p> --joiner <j> --pioneer <name> --granter nodeops \
#       [--block-sync|--state-sync] [--convert-to-validator]
#
# NAMED FOR WHAT IT WRAPS.  It takes nth_node_bringup's arguments and drives its phases; the only
# thing it adds is a ceremony in the middle.  The signing itself is not here -- that is
# foundation_multisig_sponsor_node.sh, the multisig counterpart of the foundation_sponsor_node.sh
# that phase 4 runs for a single-key granter.
#
# WHY THIS EXISTS.  fleet_bringup_with_tests.sh refuses --mainnet-source with
# --foundation-sponsored, and its reasoning is right: the sponsoring bucket is a multisig, that
# script signs on the PRIMARY, and a script that could sign for the sponsor would have to hold the
# sponsor's keys -- which is the property the multisig exists to prevent.
#
# A TEST FLEET IS THE ONE PLACE THAT DOES NOT APPLY, because this workstation holds every member
# key, exactly the arrangement a real bucket must never allow.  So the automation lives here in
# testscripts/, clearly marked, rather than weakening the driver.  The real operator procedure is
# scripts/sponsor_join_node.sh and docs/HOWTO-ADD-LAUNCH-CHAIN-NODE.md.
#
# THE SHAPE, and why it cannot be a --test-local entry.  A sponsored joiner's address does not
# exist until nth_node phase 3 mints it, and phase 5 BLOCKS waiting for the grant -- so the
# ceremony has to happen BETWEEN phases, per joiner.  --test-local only fires after a joiner has
# finished, which is too late.  Hence:
#
#     nth_node --until 3   ->   ceremony (here)   ->   nth_node --from 5 --until 8
#
# THIS SCRIPT IS ONLY THE ORCHESTRATION.  The sponsorship itself -- the fee grant, and the
# self-bond a validator needs because no grant covers staked principal -- is
# testscripts/foundation_multisig_sponsor_node.sh, the multisig counterpart of what phase 4
# normally runs on the primary (testscripts/foundation_sponsor_node.sh).
#
set -u
# HERE, NOT SCRIPT_DIR.  scripts/setup_env.sh sets SCRIPT_DIR="${0:A:h}" itself, and when it is
# SOURCED that expands to ITS OWN directory -- so SCRIPT_DIR silently becomes scripts/ the moment
# the line below runs.  References of the form $HERE/../scripts/x survive that by accident
# (scripts/../scripts is still scripts), which is why this went unnoticed; a reference to a SIBLING
# in testscripts/ does not, and fails with "no such file or directory: .../scripts/<sibling>".
HERE="${0:A:h}"
source "$HERE/../scripts/setup_env.sh" > /dev/null 2>&1 || true
QBIN="${qadenabin:-$HOME/qadena/bin}/qadenad"
HOME_DIR="${QADENAHOME:-$HOME/qadena}"

# BLOCK-SYNC IS THE ABSENCE OF A FLAG, not a flag.  nth_node_bringup takes --state-sync and
# nothing else; passing a literal --block-sync makes it exit with "unknown option".  Held as an
# ARRAY so the empty case forwards nothing at all.
PRIMARY="" JOINER="" PIONEER="" GRANTER="" CONVERT=0 EXTRA=() SYNC_ARG=()
# Forwarded to nth_node_bringup: the node keyring's passphrase, needed once client.toml asks for
# `file`, and the self-bond amount, whose default is a devnet figure a launch funder does not hold.
KEYRING_PASSFILE="" STAKE=""
# WHERE THE SPONSORING BUCKET'S KEY LIVES.  On a devnet the granter is `treasury`, a key in the
# node's own ~/qadena.  On a launch chain it is a bucket MULTISIG in the COORDINATOR keyring, which
# is a different home and an encrypted backend -- so looking it up in ~/qadena answers
# "'nodeops' is not a key in this keyring" for a key that is right there in the other one.
COORD_HOME=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --primary) PRIMARY="$2"; shift 2 ;;
        --joiner)  JOINER="$2"; shift 2 ;;
        --pioneer) PIONEER="$2"; shift 2 ;;
        --granter) GRANTER="$2"; shift 2 ;;
        --block-sync) SYNC_ARG=(); shift ;;
        --state-sync) SYNC_ARG=(--state-sync); shift ;;
        --convert-to-validator) CONVERT=1; shift ;;
        --keyring-passfile) KEYRING_PASSFILE="$2"; shift 2 ;;
        --coord-home) COORD_HOME="$2"; shift 2 ;;
        --stake) STAKE="$2"; shift 2 ;;
        --seed2) EXTRA+=(--seed2 "$2"); shift 2 ;;
        -h|--help) sed -n '3,32p' "$0"; exit 0 ;;
        *) print -u2 "unknown option: $1"; exit 1 ;;
    esac
done
[[ -n "$PRIMARY" && -n "$JOINER" && -n "$PIONEER" && -n "$GRANTER" ]] \
    || { print -u2 "need --primary, --joiner, --pioneer and --granter; see --help"; exit 1 }

# EXPORTED, NOT PASSED.  multisig_sign.sh and foundation_multisig_sponsor_node.sh both read
# QADENAHOME / QADENA_KEYRING_BACKEND / QADENA_KEYRING_PASS from the environment -- the same way
# foundation_scripts/sec_veritas_before_step_1.sh points them at the coordinator keyring.
LK_BACKEND="${QADENA_KEYRING_BACKEND:-test}"
if [[ -n "$COORD_HOME" ]]; then
    HOME_DIR="$COORD_HOME"
    LK_BACKEND="file"
    export QADENAHOME="$COORD_HOME"
    export QADENA_KEYRING_BACKEND="$LK_BACKEND"
    if [[ -n "$KEYRING_PASSFILE" ]]; then
        [[ -r "$KEYRING_PASSFILE" ]] || { print -u2 "cannot read --keyring-passfile $KEYRING_PASSFILE"; exit 1 }
        QADENA_KEYRING_PASS=$(head -1 "$KEYRING_PASSFILE")
        export QADENA_KEYRING_PASS
    fi
fi
# Feeds the passphrase when the backend needs one; zsh builtins, so it never reaches `ps`.
lk() {
    if [[ "$LK_BACKEND" == "file" && -n "${QADENA_KEYRING_PASS:-}" ]]; then
        { repeat 16 print -r -- "$QADENA_KEYRING_PASS" } 2>/dev/null \
            | "$QBIN" --home "$HOME_DIR" --keyring-backend "$LK_BACKEND" "$@" 2>/dev/null
    else
        "$QBIN" --home "$HOME_DIR" --keyring-backend "$LK_BACKEND" "$@" 2>/dev/null
    fi
}
ph() { ssh -o ConnectTimeout=15 "$PRIMARY" "bash -lc $(printf '%q' "\$HOME/qadena/bin/qadenad --home \$HOME/qadena $* --node tcp://localhost:26657")" 2>/dev/null | tr -d '\r' }

# THE GRANTER IS PASSED TO nth_node AS AN ADDRESS.  Both of its funding branches resolve the
# granter with `keys show` ON THE PRIMARY, and the primary does not hold bucket keys -- an address
# is the only form that works there.
GADDR=$(lk keys show "$GRANTER" -a)
[[ "$GADDR" == qadena1* ]] || { print -u2 "'$GRANTER' is not a key in this keyring"; exit 1 }
# Checked HERE as well as in the sponsor script, because failing now costs nothing and failing
# later costs a minted pioneer name -- the chain keeps those forever, even after the node is wiped.
[[ -n "$(lk keys show "$GRANTER" --output json | jq -r '.pubkey | fromjson? // . | .threshold // empty')" ]] \
    || { print -u2 "'$GRANTER' is not a multisig key in this keyring"; exit 1 }
CHAIN=$(ph status | jq -r '.node_info.network // empty')
[[ -n "$CHAIN" ]] || { print -u2 "cannot read the chain-id from $PRIMARY"; exit 1 }

print "sponsored join: $PIONEER on ${JOINER##*@}, sponsored by $GRANTER ($GADDR)"
print "  chain $CHAIN via $PRIMARY"

nthargs=(--primary "$PRIMARY" --joiner "$JOINER" --pioneer "$PIONEER"
         --foundation-sponsored "$GADDR" "${SYNC_ARG[@]}" "${EXTRA[@]}")
(( CONVERT )) && nthargs+=(--convert-to-validator)
[[ -n "$KEYRING_PASSFILE" ]] && nthargs+=(--keyring-passfile "$KEYRING_PASSFILE")
[[ -n "$STAKE" ]] && nthargs+=(--stake "$STAKE")

# ---------------------------------------------------------------- 1. mint the key, then stop
print ""
print "=== phases 1-3: mint $PIONEER and stop for the ceremony ==="
"$HERE/nth_node_bringup.sh" "${nthargs[@]}" --from 1 --until 3 || exit 1

# NO PINNED BACKEND.  The joiner's client.toml decides, and on a `file` node the key is not in
# keyring-test at all.  The passphrase is fed when one was given; qadenad ignores extra stdin.
if [[ -n "$KEYRING_PASSFILE" ]]; then
    JADDR=$(ssh -o ConnectTimeout=15 "$JOINER" "bash -lc 'for _ in \$(seq 8); do cat .qadena-join-keyring-pass 2>/dev/null; done | \$HOME/qadena/bin/qadenad --home \$HOME/qadena keys show $PIONEER -a'" 2>/dev/null | tr -d '\r')
else
    JADDR=$(ssh -o ConnectTimeout=15 "$JOINER" "bash -lc '\$HOME/qadena/bin/qadenad --home \$HOME/qadena --keyring-backend test keys show $PIONEER -a'" 2>/dev/null | tr -d '\r')
fi
[[ "$JADDR" == qadena1* ]] || { print -u2 "could not read $PIONEER's address from $JOINER"; exit 1 }
print "  joiner address: $JADDR"

# ---------------------------------------------------------------- 2. sponsorship, from here
# THE CEREMONY ITSELF IS NOT THIS SCRIPT'S JOB.  It is phase 4's job, done for a multisig:
# testscripts/foundation_multisig_sponsor_node.sh is the counterpart of
# testscripts/foundation_sponsor_node.sh, which is what nth_node's phase 4 runs on the primary for a
# single-key granter.  This script only knows WHEN to call it -- between phase 3, which mints the
# address, and phase 5, which blocks waiting for the grant.
print ""
print "=== sponsorship: $GRANTER signs on THIS workstation (TEST FLEET ONLY) ==="

# The bond is min-self-delegation EXACTLY, read from the joiner's own config.yml.  A sponsored node
# handed a large liquid balance can pay its own gas, which is not sponsorship.
bond_arg=()
if (( CONVERT )); then
    FLOOR=$(ssh -o ConnectTimeout=15 "$JOINER" "dasel -f \$HOME/qadena/config/config.yml 'validators.first().app.min-self-delegation'" 2>/dev/null | tr -d '\r"')
    [[ "$FLOOR" == <-> ]] || { print -u2 "could not read min-self-delegation from $JOINER (got '$FLOOR')"; exit 1 }
    print "  self-bond: ${FLOOR}aqdn (min-self-delegation, exact)"
    bond_arg=(--self-bond "${FLOOR}aqdn")
fi

QADENA_CHAIN_ID="$CHAIN" "$HERE/foundation_multisig_sponsor_node.sh" \
    --node "$JADDR" --granter "$GRANTER" --via "$PRIMARY" "${bond_arg[@]}" || exit 1

# ---------------------------------------------------------------- 3. finish the join
print ""
print "=== phases 5-8: join, bond, agree ==="
"$HERE/nth_node_bringup.sh" "${nthargs[@]}" --from 5 --until 8 || exit 1

print ""
print "DONE.  $PIONEER = $JADDR  (sponsored by $GRANTER, zero liquid balance by design)"
