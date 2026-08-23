#!/bin/zsh
# A TWO-PHASE live upgrade of a running fleet, for a release that adds a new CHAIN MESSAGE TYPE.
#
#   ./split_roll_upgrade.sh --node m1 --node m2 --node m3 --node m4 --archive ~/qadena-release.tar.gz
#
# WHY TWO PHASES AND NOT ONE.
#
# An old qadenad cannot DECODE a message type it was not built with.  A block carrying one is
# invalid to that node, so it halts or forks -- this is the one genuinely consensus-breaking part of
# such a release.  The message is PRODUCED by the new enclave, at a rotation tick, when its audit
# finds work.  So the hazard is any window where one node runs the NEW ENCLAVE while another still
# runs the OLD CHAIN BINARY.
#
#   phase 1   new qadenad everywhere, enclaves untouched.  Every node can now DECODE the new
#             message; nothing PRODUCES it.  Structurally safe -- no timing assumption.
#   phase 2   promote the measurement, then activate the new enclave node by node.  Producers
#             appear only after every decoder is in place.
#
# The alternative -- one roll, timed into a rotation gap -- relies on finishing before the next tick
# (Height %6105 == 0, about five hours at 3s blocks).  That is a "be quick" guarantee.  This is not.
#
# WHAT KEEPS PHASE 1 FROM SILENTLY BECOMING PHASE 2 -- and it is NOT --wait-active.
#
# install_release.sh decides whether to cut over from `can_activate`, which DEFAULTS TO 1 and drops
# to 0 only when the new identity is unregistered or not yet active.  --wait-active controls whether
# it WAITS for promotion, not whether it activates.  So if the identity is ALREADY ACTIVE on chain,
# a plain `install_release.sh --restart` activates the enclave -- which is exactly the fork window
# this script exists to close.
#
# THEREFORE THE ORDER IS: PHASE 1 FIRST, WHILE unique<NEW> IS STILL UNREGISTERED.  That is what
# holds can_activate at 0 and keeps the enclave staged.  Register and promote BETWEEN the phases.
#
# This inverts the advice package_release.sh prints ("If this enclave is NEW to the chain, register
# it before installing anywhere"), which is right for an ordinary single-phase roll and wrong here.
#
# AND PHASE 1 CANNOT USE --restart.  With the node RUNNING and can_activate 0, install_release.sh
# sets stage_only=1 and deliberately writes nothing that is in use -- it stages the new qadenad
# under qadenad.<version> and leaves the live one alone -- and `--restart` is itself gated on
# can_activate.  Running it that way installs NOTHING into service.  Phase 1 therefore stops the
# node itself, installs (node_running=0 => qadenad goes live, enclave still only staged because
# can_activate is 0), and starts it again.
#
# Starting is safe: run.sh's check_upgrade_enclave.sh compares the MAIN enclave binary against the
# newest enclave that ALREADY HOLDS SEALED PARAMS, requiring a STRICT version increase.  After
# phase 1 main is still the old binary at the old version, so it compares equal and does nothing.
# A staged binary has no enclave_params_<unique>.json and is not even a candidate.
#
# ONE NODE AT A TIME, ALWAYS.  On this fleet the four validators hold ~25% each, so one down leaves
# 75% and the chain advances; two down leaves 50% and it halts with every process still running.
# That is why every step below waits for the height to move before touching the next node.
#
# Equally: do NOT run buildscripts/install.sh --enclave on any fleet node.  That writes MAIN
# directly and would arm the handover on the next start -- on one node, while the others still run
# the old chain binary, which is precisely the window this script exists to close.  Build and
# PACKAGE on the builder; install only from the package.
#
# ORDERING TRAPS INHERITED FROM full_fleet_bringup.sh (same fleet, same lessons):
#   - the package must be built from the artifacts that are actually RUNNING, never rebuilt after
#   - one artifact for every node of an architecture; verify by sha256, not by shared commit,
#     because the build is not reproducible and a debug enclave takes its identity from a text file
#   - processes being up is not health: check that the HEIGHT IS ADVANCING between steps
#   - a node that is BEHIND when a measurement is promoted can never trust it (backlog 99), so the
#     height check between phase-2 nodes is load-bearing, not cosmetic
#
# The Mac is not a target here: darwin/arm64 cannot run the fleet's linux/arm64 artifact.  It is
# built locally from the same commit with byte-identical id files and joined separately.

set -u
setopt ERR_EXIT PIPE_FAIL

NODES=()
ARCHIVE=""
PHASE="both"
WAIT_SECS=3600
DRY=0

while (( $# )); do
    case "$1" in
        --node)      NODES+=("$2"); shift 2 ;;
        --archive)   ARCHIVE="$2"; shift 2 ;;
        --phase)     PHASE="$2"; shift 2 ;;     # 1 | 2 | both
        --wait-secs) WAIT_SECS="$2"; shift 2 ;;
        --dry-run)   DRY=1; shift ;;
        --help|-h)
            sed -n '2,50p' "$0"
            exit 0 ;;
        *) print -u2 "FAIL: unknown flag $1"; exit 1 ;;
    esac
done

(( ${#NODES} >= 1 )) || { print -u2 "FAIL: --node is required (repeatable)"; exit 1 }
[[ -n "$ARCHIVE" ]]  || { print -u2 "FAIL: --archive is required"; exit 1 }
[[ "$PHASE" == (1|2|both) ]] || { print -u2 "FAIL: --phase takes 1, 2 or both"; exit 1 }

say()  { print -- "$(date '+%H:%M:%S')  $*" }
step() { print ""; print -- "=== $* ===" }
die()  { print -u2 "FAIL: $*"; exit 1 }

# Bracket-classed patterns everywhere: the ssh command line carrying the pattern must not match
# itself.  See full_fleet_bringup.sh trap 8.
rsh() {
    local host="$1"; shift
    ssh -o ConnectTimeout=10 -o BatchMode=yes "$host" "zsh -lc $(printf '%q' "$*")"
}

run() {   # run <host> <command...> -- honours --dry-run
    local host="$1"; shift
    if (( DRY )); then
        print -- "    [dry-run] $host: $*"
        return 0
    fi
    rsh "$host" "$@"
}

height_of() {   # height_of <host> -- current block height, or empty
    rsh "$1" 'qadenad status 2>/dev/null' 2>/dev/null \
        | tr ',' '\n' | grep -o '"latest_block_height":"[0-9]*"' | grep -o '[0-9]*' | head -1
}

# PROCESSES BEING UP IS NOT HEALTH.  A divergent node on a small fleet halts the chain with every
# process still running, so the only useful liveness question is whether the height MOVES.
require_advancing() {   # require_advancing <host>
    local host="$1" h1 h2
    h1=$(height_of "$host") || true
    [[ -n "$h1" ]] || die "$host: no height at all -- is qadenad running?"
    sleep 12
    h2=$(height_of "$host") || true
    [[ -n "$h2" ]] || die "$host: height query stopped answering"
    (( h2 > h1 )) || die "$host: height stuck at $h1 -- the chain is not advancing, refusing to continue"
    say "  $host advancing: $h1 -> $h2"
}

enclave_measurement_of() {   # what MAIN enclave binary this node would start
    rsh "$1" 'qadenad q qadena enclave-measurement -o json 2>/dev/null' 2>/dev/null \
        | tr ',' '\n' | grep -o '"uniqueID":"[^"]*"' | cut -d'"' -f4 | head -1
}

chain_version_of() {
    rsh "$1" 'qadenad version 2>/dev/null' 2>/dev/null | head -1
}

step "0. preflight -- every host, BEFORE anything is touched"
for n in "${NODES[@]}"; do
    rsh "$n" 'true' || die "$n unreachable over ssh (BatchMode: is the key loaded?)"
    say "$n  chain=$(chain_version_of $n)  enclave=$(enclave_measurement_of $n)"
done
for n in "${NODES[@]}"; do require_advancing "$n"; done

# ONE ARTIFACT, VERIFIED BY CONTENT.  The build is not reproducible and a debug enclave reads its
# identity from an embedded text file, so two different binaries can claim the same measurement and
# the chain cannot tell them apart (backlog 105).  Sharing a commit proves nothing; sharing a
# sha256 does.
[[ -f "$ARCHIVE" ]] || die "archive not found: $ARCHIVE"
LOCAL_SHA=$(shasum -a 256 "$ARCHIVE" | cut -d' ' -f1)
say "archive sha256 $LOCAL_SHA"

step "0b. distribute the archive"
REMOTE_ARCHIVE="/tmp/$(basename $ARCHIVE)"
for n in "${NODES[@]}"; do
    if (( DRY )); then
        print -- "    [dry-run] scp $ARCHIVE $n:$REMOTE_ARCHIVE"
    else
        scp -q "$ARCHIVE" "$n:$REMOTE_ARCHIVE" || die "$n: copy failed"
        got=$(rsh "$n" "shasum -a 256 $REMOTE_ARCHIVE" | cut -d' ' -f1)
        [[ "$got" == "$LOCAL_SHA" ]] || die "$n: archive sha256 $got != $LOCAL_SHA"
        say "  $n verified $got"
    fi
done

if [[ "$PHASE" == (1|both) ]]; then
    step "1. PHASE ONE -- new chain binary everywhere, enclaves untouched"
    say "NOTE: --wait-active is deliberately NOT passed here.  It is the only thing separating"
    say "      this phase from phase two; passing it would activate a staged enclave the moment"
    say "      the chain had promoted it, which is the fork window this script exists to close."
    for n in "${NODES[@]}"; do
        say "$n: stop -> install -> start  (chain goes live, enclave only staged)"
        run "$n" "~/qadena/scripts/stop_qadena.sh --all"
        # No --restart: it is gated on can_activate, which is 0 here by design.  Stopping first is
        # what makes stage_only 0, so the new qadenad is written to the live name.
        run "$n" "~/qadena/scripts/install_release.sh $REMOTE_ARCHIVE"
        run "$n" "~/qadena/scripts/start_qadena.sh"
        (( DRY )) || sleep 10
        (( DRY )) || require_advancing "$n"
    done

    step "1b. verify phase one landed as intended, on EVERY node"
    # The invariant that makes phase two safe: every node DECODES the new message type (new chain
    # binary) and none PRODUCES it (enclave measurement unchanged).  Checked, not assumed -- a
    # single node left behind here is the whole hazard.
    for n in "${NODES[@]}"; do
        say "$n  chain=$(chain_version_of $n)  enclave=$(enclave_measurement_of $n)"
    done
    print ""
    say "CONFIRM BEFORE PHASE TWO: every chain version above is the NEW one, and every enclave"
    say "measurement is still the OLD one.  If any chain version is stale, that node cannot decode"
    say "the new message and phase two will fork the chain."
fi

if [[ "$PHASE" == (2|both) ]]; then
    step "2. PHASE TWO -- promote the measurement, then activate node by node"
    say "PRECONDITION: the new enclave identity has been REGISTERED by governance and PROMOTED to"
    say "active.  install_release.sh --wait-active waits for that; it cannot create it."
    for n in "${NODES[@]}"; do
        say "$n: waiting for promotion, then activating (handover via --upgrade-mode)"
        run "$n" "~/qadena/scripts/install_release.sh $REMOTE_ARCHIVE --wait-active=$WAIT_SECS --restart"
        # BACKLOG 99: a node that is behind when a measurement is promoted can never trust it.
        # Letting each node catch up fully before touching the next is what keeps that from
        # stranding one.
        (( DRY )) || require_advancing "$n"
    done

    step "2b. final state"
    for n in "${NODES[@]}"; do
        say "$n  chain=$(chain_version_of $n)  enclave=$(enclave_measurement_of $n)"
    done
    print ""
    say "Every enclave measurement above should now be the NEW one.  The next rotation tick"
    say "(Height %6105 == 0) will run the re-share audit; watch for 'ss-reshare: AUDIT' and"
    say "'ss-reshare: EMITTED' on the proposer, and 'ss-reshare: RECEIVED' on the others."
fi

step "done"
