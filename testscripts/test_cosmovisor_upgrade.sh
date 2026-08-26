#!/bin/zsh
# The cosmovisor end-to-end: a managed fleet upgrades BY GOVERNANCE at a height, and a fresh
# joiner block-syncs from genesis ACROSS that height -- old binaries for old blocks, a swap at H,
# new binaries to the tip.
#
#   ./testscripts/test_cosmovisor_upgrade.sh \
#       --primary alvillarica@192.168.86.162 --joiner alvillarica@192.168.86.154 \
#       --from-ref <ref> --to-ref <ref>
#
# WHAT A PASS PROVES, and why it is the payoff of the whole cosmovisor effort: the exact scenario
# a427b26f made impossible.  There, a consensus-affecting change went out by binary swap with no
# height; every joiner then died at the first block whose gas the new binary computed differently
# (block 3 with the check, 12211 without), and the chain had to be restarted.  Here the boundary
# is ON CHAIN: the joiner's genesis/bin executes blocks < H, x/upgrade halts it AT H with the
# plan's name, cosmovisor swaps to the staged dir, and the new binary carries on -- every block
# executed by the binary that originally executed it, with earliest_block_height==1 proving no
# snapshot shortcut.
#
# Relationship to test_replay_across_upgrade.sh: that one performs a deliberate UNSCHEDULED swap
# on unmanaged hosts and must fail when the change is consensus-affecting -- the detector.  This
# one performs a SCHEDULED swap on managed hosts and must pass -- the mechanism.  Run both when
# validating a release: a change that fails the detector should sail through this.
#
# SCOPE: the from/to refs here differ by CHAIN version (same enclave measurement).  A joiner
# across an ENCLAVE-measurement boundary is documented out of scope -- its genesis-era enclave
# cannot sync-enclave from seeds running the new measurement (the seed-measurement gate), and
# that limitation pre-dates cosmovisor.  The FLEET side of a chain+enclave upgrade is covered by
# rolling_upgrade --via-governance itself.

set -u
SCRIPT_DIR="${0:A:h}"
FLEET_NAME="cosmovisor-upgrade"
source "$SCRIPT_DIR/fleet_lib.sh"

PRIMARY=""; JOINER=""; FROM_REF=""; TO_REF=""; RUN_DIR=""
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
            print "Usage: test_cosmovisor_upgrade.sh --primary <[user@]host> --joiner <[user@]host>"
            print "                                   --from-ref <ref> --to-ref <ref> [--traffic <cmd>]"
            exit 0 ;;
        *) print -u2 "unknown option: $1"; exit 1 ;;
    esac
done
[[ -n "$PRIMARY" && -n "$JOINER" && -n "$FROM_REF" && -n "$TO_REF" ]] \
    || { print -u2 "--primary, --joiner, --from-ref and --to-ref are all required"; exit 1 }

[[ -n "$RUN_DIR" ]] || RUN_DIR="$HOME/qadena-fleet-runs/cosmovisor-$(date -u +%Y%m%d-%H%M%S)"
mkdir -p "$RUN_DIR" || exit 1
STATUS="$RUN_DIR/status.txt"
note "run started: $0 $*"
info "primary   $PRIMARY"
info "joiner    $JOINER"
info "from-ref  $FROM_REF   to-ref  $TO_REF"
info "run dir   $RUN_DIR"

# ---------------------------------------------------------------------------------------------
stage "A. preflight"
vfrom=$(git -C "$SCRIPT_DIR/.." show "${FROM_REF}:cmd/qadenad/version.txt" 2>/dev/null | tr -d '\n')
vto=$(git   -C "$SCRIPT_DIR/.." show "${TO_REF}:cmd/qadenad/version.txt"   2>/dev/null | tr -d '\n')
[[ -n "$vfrom" && -n "$vto" ]] || fail "cannot read cmd/qadenad/version.txt at the refs -- fetched?"
info "chain version  $FROM_REF=$vfrom  ->  $TO_REF=$vto  (plan will be v$vto)"
[[ "$vfrom" != "$vto" ]] || fail "both refs carry $vfrom -- no version boundary; --via-governance would refuse and this run would prove nothing"
for h in "$PRIMARY" "$JOINER"; do
    rsh_user "$h" 'true' >/dev/null 2>&1 || fail "cannot ssh to $h"
done
# The joiner's previous install is archived exactly as the replay test learned to (its first run
# reported a stale chain at height 5506 as a measurement mismatch).
jhome=$(rsh_user "$JOINER" 'print $HOME' | tr -d '\r')
if rsh_user "$JOINER" "test -d $jhome/qadena"; then
    rsh_user "$JOINER" "test -x $jhome/qadena/scripts/stop_qadena.sh" \
        && rsh_user "$JOINER" "$jhome/qadena/scripts/stop_qadena.sh --all" >/dev/null 2>&1
    left=$(ssh -o ConnectTimeout=10 "$JOINER" 'ps -eo pid,cmd | grep -E "qaden[a]d|cosmoviso[r] run|eg[o] run|ego-hos[t]" | grep -v grep | wc -l' | tr -d '\r')
    [[ "$left" == "0" ]] || fail "$JOINER still has $left process(es); kill by PID and re-run"
    stamp=$(date -u +%Y%m%d-%H%M%S)
    rsh_user "$JOINER" "mv $jhome/qadena $jhome/qadena.pre-cosmovisor.$stamp.bak" || fail "could not archive $JOINER's ~/qadena"
    info "$JOINER: archived"
fi
info "preflight ok"

# ---------------------------------------------------------------------------------------------
stage "B. managed primary at $FROM_REF, fresh chain"
"$SCRIPT_DIR/1st_node_bringup.sh" --primary "$PRIMARY" --ref "$FROM_REF" --from 1 --until 6 \
    2>&1 | tee "$RUN_DIR/stage-B.log" | while read -r l; do info "$l"; done
[[ ${pipestatus[1]} -eq 0 ]] || fail "primary bringup failed"
cosmovisor_managed_on "$PRIMARY" || fail "primary is not managed after --cosmovisor bringup"
info "primary managed: current -> $(cosmovisor_current_of "$PRIMARY")"

# ---------------------------------------------------------------------------------------------
stage "C. traffic on $vfrom -- history the joiner must later replay on OLD binaries"
rsh_user "$PRIMARY" "cd \$HOME/qv3 && $TRAFFIC" \
    2>&1 | tee "$RUN_DIR/stage-C.log" | while read -r l; do info "$l"; done
[[ ${pipestatus[1]} -eq 0 ]] || fail "traffic failed on $vfrom"

# ---------------------------------------------------------------------------------------------
stage "D. package $vfrom and install+convert the joiner (NOT started, NOT joined yet)"
# The joiner's genesis/bin must be the CHAIN-GENESIS-era binaries.  Package before the upgrade,
# install on the joiner, convert -- it sits stopped until stage G.
"$SCRIPT_DIR/1st_node_bringup.sh" --primary "$PRIMARY" --joiner "$JOINER" --from 7 --until 8 \
    2>&1 | tee "$RUN_DIR/stage-D.log" | while read -r l; do info "$l"; done
[[ ${pipestatus[1]} -eq 0 ]] || fail "package/install on the joiner failed"
cosmovisor_managed_on "$JOINER" || fail "joiner is not managed after phase-8 conversion"

# ---------------------------------------------------------------------------------------------
stage "E. upgrade the primary to $TO_REF by governance"
info "moving $PRIMARY's checkout to $TO_REF (detached)"
rsh_user "$PRIMARY" "cd \$HOME/qv3 && git fetch --all --tags --quiet && \
    { git checkout --quiet --detach origin/$TO_REF 2>/dev/null || git checkout --quiet --detach $TO_REF; } && \
    git log --oneline -1" 2>&1 | while read -r l; do info "$l"; done
[[ ${pipestatus[1]} -eq 0 ]] || fail "could not check out $TO_REF on $PRIMARY"

"$SCRIPT_DIR/rolling_upgrade.sh" --node "$PRIMARY" --via-governance --build-from "$PRIMARY" \
    2>&1 | tee "$RUN_DIR/stage-E-upgrade.log" | while read -r l; do info "$l"; done
[[ ${pipestatus[1]} -eq 0 ]] || fail "--via-governance failed"
cur=$(cosmovisor_current_of "$PRIMARY")
[[ "$cur" == *"upgrades/v$vto"* ]] || fail "primary's current -> '$cur', expected upgrades/v$vto"
info "primary swapped: current -> $cur"

# ---------------------------------------------------------------------------------------------
stage "F. traffic on $vto -- so the joiner must CROSS the boundary, not stop at it"
rsh_user "$PRIMARY" "cd \$HOME/qv3 && $TRAFFIC" \
    2>&1 | tee "$RUN_DIR/stage-F.log" | while read -r l; do info "$l"; done
[[ ${pipestatus[1]} -eq 0 ]] || fail "traffic failed on $vto"

# ---------------------------------------------------------------------------------------------
stage "G. stage v$vto on the joiner, then block-sync it from genesis"
# The upgrade package landed on the primary at /tmp during --via-governance's distribute; relay
# it (workstation in the middle -- the nodes need not reach each other's accounts).
# Constrained to THIS upgrade's version: /tmp accumulates archives from every previous run on
# this host, and `ls -t | head -1` would happily relay one of those to the joiner -- which would
# then stage binaries that do not match the plan the chain scheduled.
pkg=$(rsh_user "$PRIMARY" "ls -t /tmp/qadena-full-$vto-*.tar.gz 2>/dev/null | head -1" | tr -d '\r')
[[ -n "$pkg" ]] || fail "no package on the primary to relay"
base=$(basename "$pkg")
ssh -o ConnectTimeout=10 "$PRIMARY" "cat $pkg" | ssh -o ConnectTimeout=10 "$JOINER" "cat > /tmp/$base" \
    || fail "could not relay the package to $JOINER"
rsh_user "$JOINER" "~/qadena/scripts/install_release.sh /tmp/$base --stage-upgrade v$vto > /tmp/stage_join.log 2>&1 < /dev/null" \
    || { rsh_user "$JOINER" 'tail -15 /tmp/stage_join.log' | sed 's/^/    /'; fail "staging v$vto on the joiner failed"; }
info "joiner staged v$vto"

# NO --state-sync: block-sync from genesis is the entire point (a snapshot would start ABOVE the
# boundary and prove nothing).
"$SCRIPT_DIR/nth_node_bringup.sh" --primary "$PRIMARY" --joiner "$JOINER" --from 1 --until 5 \
    2>&1 | tee "$RUN_DIR/stage-G-join.log" | while read -r l; do info "$l"; done
joinrc=${pipestatus[1]}

# ---------------------------------------------------------------------------------------------
stage "VERDICT"
[[ $joinrc -eq 0 ]] || {
    # Show whether it at least reached the halt -- a failure AT the boundary is a different bug
    # than one before it.
    rsh_user "$JOINER" 'sed "s/\x1b\[[0-9;]*m//g" $HOME/qadena/logs/qadena.log 2>/dev/null | grep -a "UPGRADE .* NEEDED" | tail -1' | sed 's/^/    /'
    fail "the joiner did not complete the block-sync (rc=$joinrc)"
}

hj=$(height_of "$JOINER"); hp=$(height_of "$PRIMARY")
earliest=$(rsh_user "$JOINER" 'curl -s --max-time 5 localhost:26657/status | jq -r ".result.sync_info.earliest_block_height // empty"' | tr -d '\r')
jcur=$(cosmovisor_current_of "$JOINER")
halted=$(rsh_user "$JOINER" 'sed "s/\x1b\[[0-9;]*m//g" $HOME/qadena/logs/qadena.log 2>/dev/null | grep -ac "UPGRADE .* NEEDED"' | tr -d '\r')

[[ "$earliest" == "1" ]] || fail "joiner's earliest block is ${earliest:-?}, not 1 -- it did not replay from genesis"
[[ "$jcur" == *"upgrades/v$vto"* ]] || fail "joiner's current -> '$jcur' -- it never swapped, so it cannot have crossed the boundary"
[[ "${halted:-0}" -ge 1 ]] || fail "the joiner's log never shows the UPGRADE NEEDED halt -- it reached the tip without crossing a boundary, which means the boundary was not where this test thinks"
require_live "$JOINER" "verdict"

info "joiner: replayed from genesis (earliest=1), halted at the plan height (UPGRADE NEEDED seen),"
info "        swapped (current -> $jcur), and is live at $hj (primary $hp)"
note "PASSED: a genesis joiner crossed the governance upgrade boundary"
print ""
print "PASS($FLEET_NAME): history built on $vfrom replays under cosmovisor, swapping to $vto at the scheduled height"
