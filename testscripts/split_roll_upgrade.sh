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
# WHAT KEEPS PHASE 1 FROM SILENTLY BECOMING PHASE 2.
#
# install_release.sh only ever stages the enclave under its measurement name
# (bin/qadenad_enclave.<unique>); it replaces bin/qadenad_enclave -- the MAIN binary, the only one
# that matters -- in exactly two cases: a fresh install, or when the chain has already PROMOTED the
# new identity (--wait-active).  And run.sh's check_upgrade_enclave.sh compares the MAIN binary
# against the newest enclave that ALREADY HOLDS SEALED PARAMS; a staged binary has no
# enclave_params_<unique>.json, so it is not even a candidate.
#
# Therefore: PHASE 1 MUST NOT PASS --wait-active.  That flag is the whole difference between the
# phases, and it is asserted below rather than merely intended.
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
        say "$n: installing (chain live, enclave staged)"
        run "$n" "~/qadena/scripts/install_release.sh $REMOTE_ARCHIVE --restart"
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
