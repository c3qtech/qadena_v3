#!/bin/zsh
# Does a chain built at ref A stay REPLAYABLE by a binary built at ref B?
#
#   ./testscripts/test_replay_across_upgrade.sh \
#       --primary alvillarica@192.168.86.162 \
#       --joiner  alvillarica@192.168.86.154 \
#       --from-ref v1.1.16 --to-ref main
#
# ---------------------------------------------------------------------------------------------
# THE BUG THIS EXISTS FOR, and it went unnoticed for four days.
#
# a427b26f added ONE gas-metered store read to PioneerUpdateIntervalPublicKeyID -- a security check,
# correct on its own terms -- and shipped it by binary swap with no upgrade height.  Gas is
# consensus: it lands in feemarket's stored block gas, which lands in the app hash.  So every block
# executed before the swap became unreplayable by every binary after it.
#
#   block 3      executed by 1.1.16  ->  448698 gas
#   block 12211  executed by 1.1.17  ->  218616 gas   (+1993 = 1000 flat + 3/byte * 331)
#
# No single binary satisfies both.  Two joiners died proving it: one halted at block 3 with the
# check compiled in, the other at 12211 with it commented out.  The chain had to be restarted.
#
# WHY NOTHING CAUGHT IT.  The existing joiner tests build a chain and join it with ONE binary
# version, so the history and the replayer always agree.  The failure needs a VERSION BOUNDARY
# INSIDE the chain's own history, which no test produced.  This produces one deliberately.
#
# WHAT A PASS MEANS: a joiner replaying from genesis crossed a boundary where the rules changed and
# still computed every app hash the chain recorded.  What a FAILURE means: the change between the
# two refs is consensus-affecting and needs an upgrade height (or the chain needs restarting), and
# the log will name the height where the two disagreed.
#
# THIS IS NOT A SUBSTITUTE FOR READING THE DIFF.  It answers "did this break replay", not "is this
# change consensus-affecting" -- a change can be consensus-affecting and still pass here if the
# traffic never exercises it.  Stage C and E run SS key rotations because that is what emits
# MsgPioneerUpdateIntervalPublicKeyID, the message a427b26f touched; traffic that exercises YOUR
# change is your responsibility to add.

set -u
SCRIPT_DIR="${0:A:h}"
FLEET_NAME="replay-across-upgrade"
source "$SCRIPT_DIR/fleet_lib.sh"

PRIMARY=""; JOINER=""; FROM_REF=""; TO_REF="main"; RUN_DIR=""
TRAFFIC="./testscripts/test_ss_key_rotation.sh --key-added-only"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --primary)  PRIMARY="$2"; shift 2 ;;
        --joiner)   JOINER="$2";  shift 2 ;;
        --from-ref) FROM_REF="$2"; shift 2 ;;
        --to-ref)   TO_REF="$2";   shift 2 ;;
        --traffic)  TRAFFIC="$2";  shift 2 ;;
        --run-dir)  RUN_DIR="$2";  shift 2 ;;
        --help)
            print "Usage: test_replay_across_upgrade.sh --primary <[user@]host> --joiner <[user@]host>"
            print "                                     --from-ref <ref> [--to-ref <ref>]"
            print "                                     [--traffic <cmd>] [--run-dir <dir>]"
            print ""
            print "  --from-ref  the ref the chain is CREATED on.  Its history is what must stay"
            print "              replayable."
            print "  --to-ref    the ref the fleet is upgraded to, and the one the joiner runs."
            print "              Default main."
            print "  --traffic   command run on the primary before AND after the upgrade, to put"
            print "              the messages your change touches into the history.  Default is an"
            print "              SS key rotation, which emits MsgPioneerUpdateIntervalPublicKeyID."
            exit 0 ;;
        *) print -u2 "unknown option: $1"; exit 1 ;;
    esac
done

[[ -n "$PRIMARY"  ]] || { print -u2 "--primary is required"; exit 1 }
[[ -n "$JOINER"   ]] || { print -u2 "--joiner is required";  exit 1 }
[[ -n "$FROM_REF" ]] || { print -u2 "--from-ref is required"; exit 1 }

[[ -n "$RUN_DIR" ]] || RUN_DIR="$HOME/qadena-fleet-runs/replay-$(date -u +%Y%m%d-%H%M%S)"
mkdir -p "$RUN_DIR" || exit 1
STATUS="$RUN_DIR/status.txt"
ln -sfn "$RUN_DIR" "$HOME/qadena-fleet-runs/latest-replay" 2>/dev/null

note "run started: $0 $*"
info "primary   $PRIMARY"
info "joiner    $JOINER"
info "from-ref  $FROM_REF"
info "to-ref    $TO_REF"
info "run dir   $RUN_DIR"

# ---------------------------------------------------------------------------------------------
stage "A. preflight -- refuse a run that cannot prove anything"

# THE REFS MUST DIFFER IN VERSION, or rolling_upgrade --chain-only refuses to roll and the run
# would report a pass having upgraded nothing.  Checked HERE, before a chain is wiped, because
# discovering it at stage D costs the whole bringup.
# BRACES ARE LOAD-BEARING.  In zsh, "$FROM_REF:cmd/..." parses the ":c" as a PARAMETER MODIFIER
# (:c resolves a command to its path), so the ref and the "c" of "cmd" vanish together and git is
# handed "HEAD~1md/qadenad/version.txt".  It fails as "ambiguous argument", which reads as a bad ref
# rather than a quoting bug -- and this file's own preflight then reports "is that ref fetched?"
# about a ref that is perfectly fine.
vfrom=$(git -C "$SCRIPT_DIR/.." show "${FROM_REF}:cmd/qadenad/version.txt" 2>/dev/null | tr -d '\n')
vto=$(git   -C "$SCRIPT_DIR/.." show "${TO_REF}:cmd/qadenad/version.txt"   2>/dev/null | tr -d '\n')
[[ -n "$vfrom" ]] || fail "cannot read cmd/qadenad/version.txt at $FROM_REF -- is that ref fetched?"
[[ -n "$vto"   ]] || fail "cannot read cmd/qadenad/version.txt at $TO_REF -- is that ref fetched?"
info "chain version  $FROM_REF=$vfrom  ->  $TO_REF=$vto"
[[ "$vfrom" != "$vto" ]] || fail \
    "both refs carry chain version $vfrom.  rolling_upgrade --chain-only refuses to roll when the \
version has not moved, so this run would upgrade nothing and pass regardless.  Bump \
cmd/qadenad/version.txt on $TO_REF."

for h in "$PRIMARY" "$JOINER"; do
    rsh_user "$h" 'true' >/dev/null 2>&1 || fail "cannot ssh to $h"
done

# ARCHIVE THE JOINER'S PREVIOUS INSTALL, and do it here rather than at stage F.
#
# Two things go wrong without it, and the first run hit both.  install.sh refuses to overwrite a
# versioned binary whose contents differ (fleet_lib trap 6), so the install fails; and if it did
# not, nth_node_bringup's phase-1 preflight compares the joiner's CURRENT enclave measurement
# against the primary's and refuses -- which is how a run that had already wiped the primary
# reported "joiner height 5506, primary height 97": the joiner was still serving the PREVIOUS
# chain, on a measurement from a build this run knows nothing about.
#
# Moved aside, never deleted: it holds a chain whose genesis this run is about to destroy, but it
# also holds a keyring, and reaping it is the operator's call.
jhome=$(rsh_user "$JOINER" 'print $HOME' | tr -d '\r')
[[ -n "$jhome" ]] || fail "could not resolve \$HOME on $JOINER"
if rsh_user "$JOINER" "test -d $jhome/qadena"; then
    rsh_user "$JOINER" "test -x $jhome/qadena/scripts/stop_qadena.sh" \
        && rsh_user "$JOINER" "$jhome/qadena/scripts/stop_qadena.sh --all" >/dev/null 2>&1
    left=$(ssh -o ConnectTimeout=10 "$JOINER" 'ps -eo pid,cmd | grep -E "qaden[a]d|eg[o] run|signer_enclav[e]" | grep -v grep | wc -l' | tr -d '\r')
    [[ "$left" == "0" ]] || fail "$JOINER still has $left node/enclave process(es); kill them BY PID and re-run"
    stamp=$(date -u +%Y%m%d-%H%M%S)
    rsh_user "$JOINER" "mv $jhome/qadena $jhome/qadena.pre-replay.$stamp.bak" \
        || fail "could not archive $JOINER's old ~/qadena"
    info "$JOINER: archived to $jhome/qadena.pre-replay.$stamp.bak"
else
    info "$JOINER: no ~/qadena to archive"
fi
info "preflight ok"

# ---------------------------------------------------------------------------------------------
stage "B. build the primary at $FROM_REF and create a FRESH chain"
"$SCRIPT_DIR/1st_node_bringup.sh" --primary "$PRIMARY" --ref "$FROM_REF" --from 1 --until 6 \
    2>&1 | tee "$RUN_DIR/stage-B-primary-$FROM_REF.log" | while read -r l; do info "$l"; done
[[ ${pipestatus[1]} -eq 0 ]] || fail "could not bring up the primary at $FROM_REF"
assert_advancing "$PRIMARY" "B"

# ---------------------------------------------------------------------------------------------
stage "C. traffic on $FROM_REF -- this is the history that must stay replayable"
rsh_user "$PRIMARY" "cd \$HOME/qv3 && $TRAFFIC" \
    2>&1 | tee "$RUN_DIR/stage-C-traffic-old.log" | while read -r l; do info "$l"; done
[[ ${pipestatus[1]} -eq 0 ]] || fail "traffic failed on $FROM_REF"
h_before=$(height_of "$PRIMARY")
info "history on $FROM_REF reaches height $h_before"
note "boundary: blocks 1..$h_before executed by $FROM_REF ($vfrom)"

# ---------------------------------------------------------------------------------------------
stage "D. roll the primary to $TO_REF -- the version boundary lands here"

# MOVE THE CHECKOUT FIRST.  rolling_upgrade.sh has no --ref: it builds whatever is checked out on
# --build-from.  Stage B left that at $FROM_REF, so without this the "upgrade" would rebuild the
# SAME code, the version check inside rolling_upgrade would refuse it, and a run that got past that
# would report a pass having created no boundary at all -- the exact false green this file exists
# to prevent.  Detached on purpose: nothing here should leave the primary on a branch that a later
# fetch could move underneath it.
info "moving $PRIMARY's checkout to $TO_REF"
rsh_user "$PRIMARY" "cd \$HOME/qv3 && git fetch --all --tags --quiet && \
    { git checkout --quiet --detach origin/$TO_REF 2>/dev/null || git checkout --quiet --detach $TO_REF; } && \
    git log --oneline -1" 2>&1 | while read -r l; do info "$l"; done
[[ ${pipestatus[1]} -eq 0 ]] || fail "could not check out $TO_REF on $PRIMARY"

vnow=$(rsh_user "$PRIMARY" 'cat $HOME/qv3/cmd/qadenad/version.txt' | tr -d '\r\n')
[[ "$vnow" == "$vto" ]] || fail \
    "after checking out $TO_REF the primary reports chain version '$vnow', expected '$vto' -- the \
checkout did not take, and rolling from here would build the wrong thing."

# NO --repo.  It is RELATIVE TO $HOME (default "qv3", used as "\$HOME/$REPO_DIR"), so passing an
# absolute path produced "$HOME/$HOME/qv3" and rolling_upgrade reported a missing version.txt as if
# the checkout were wrong.  The default is already correct.
"$SCRIPT_DIR/rolling_upgrade.sh" --node "$PRIMARY" --chain-only \
    --build-from "$PRIMARY" \
    2>&1 | tee "$RUN_DIR/stage-D-upgrade.log" | while read -r l; do info "$l"; done
[[ ${pipestatus[1]} -eq 0 ]] || fail "the rolling upgrade to $TO_REF failed"
assert_advancing "$PRIMARY" "D"

# ---------------------------------------------------------------------------------------------
stage "E. traffic on $TO_REF -- so the joiner must cross the boundary, not stop at it"
rsh_user "$PRIMARY" "cd \$HOME/qv3 && $TRAFFIC" \
    2>&1 | tee "$RUN_DIR/stage-E-traffic-new.log" | while read -r l; do info "$l"; done
[[ ${pipestatus[1]} -eq 0 ]] || fail "traffic failed on $TO_REF"
h_after=$(height_of "$PRIMARY")
info "history on $TO_REF reaches height $h_after"

# ---------------------------------------------------------------------------------------------
stage "F. package what is running, then BLOCK-SYNC a fresh joiner from genesis"
# 7 PACKAGES what is actually running, 8 INSTALLS it on the joiner.  Both, and in one call: the
# joiner must run the measurement the PRIMARY is running, which after a --chain-only roll is still
# the enclave from --from-ref.  Building on the joiner instead would produce a different
# measurement and phase 1 would refuse it -- EnclaveIdentity is keyed by measurement.
"$SCRIPT_DIR/1st_node_bringup.sh" --primary "$PRIMARY" --joiner "$JOINER" --from 7 --until 8 \
    2>&1 | tee "$RUN_DIR/stage-F-package-install.log" | while read -r l; do info "$l"; done
[[ ${pipestatus[1]} -eq 0 ]] || fail "could not package the primary and install it on $JOINER"

# NO --state-sync.  Block-sync is the whole point: a state-synced joiner starts at a snapshot ABOVE
# the boundary and never replays the blocks that disagree, so it would pass a chain that is broken.
"$SCRIPT_DIR/nth_node_bringup.sh" --primary "$PRIMARY" --joiner "$JOINER" --from 1 --until 5 \
    2>&1 | tee "$RUN_DIR/stage-F-join.log" | while read -r l; do info "$l"; done
joinrc=${pipestatus[1]}

# ---------------------------------------------------------------------------------------------
stage "VERDICT"
hj=$(height_of "$JOINER")
info "primary height $h_after, joiner height ${hj:-unknown}"

if [[ $joinrc -ne 0 || -z "$hj" ]]; then
    apphash=$(rsh_user "$JOINER" 'sed "s/\x1b\[[0-9;]*m//g" $HOME/qadena/logs/qadena.log 2>/dev/null | grep -a "wrong Block.Header.AppHash" | tail -1' | tr -d '\r')
    if [[ -n "$apphash" ]]; then
        info "$apphash"
        fail "REPLAY BROKEN across $FROM_REF -> $TO_REF.  The joiner disagreed with the recorded \
app hash, so a block executed under $vfrom does not reproduce under $vto.  The change between \
these refs is CONSENSUS-AFFECTING and needs an upgrade height, or the chain needs restarting.  \
Compare /block_results at the halting height on both nodes: identical events with different \
gas_used means a store operation was added or removed."
    fi
    fail "the joiner did not complete a block-sync from genesis (rc=$joinrc)"
fi

# It must have replayed the WHOLE history, not started above the boundary.
earliest=$(rsh_user "$JOINER" 'curl -s --max-time 5 localhost:26657/status | jq -r ".result.sync_info.earliest_block_height // empty"' | tr -d '\r')
[[ "$earliest" == "1" ]] || fail \
    "the joiner's earliest block is ${earliest:-unknown}, not 1 -- it did not replay from genesis, \
so it never crossed the boundary and this run proves nothing."

# THE BOUNDARY IS THE MINIMUM, NOT THE TARGET.  Requiring only $h_before would pass a joiner that
# crossed the boundary and then stalled one block later, which is a broken chain reported green.
# $h_after is where the primary stood when stage E finished, so reaching it means the joiner
# replayed every block this run produced -- on both sides of the boundary.
[[ "$hj" -ge "$h_before" ]] || fail \
    "the joiner reached only $hj, below the boundary at $h_before -- it never crossed."
[[ "$hj" -ge "$h_after" ]] || fail \
    "the joiner reached $hj but the primary was at $h_after when the traffic finished -- it crossed \
the boundary and then stopped, so the blocks built on $vto were not all replayed."

info "the joiner replayed blocks 1..$hj from genesis, across the $vfrom -> $vto boundary at $h_before"
note "PASSED: replay survives $FROM_REF -> $TO_REF"
print ""
print "PASS($FLEET_NAME): history built on $vfrom replays correctly under $vto"
