#!/bin/zsh
# A SIMPLE rolling upgrade of a running fleet: one node at a time, no downtime for the chain.
#
#   ./rolling_upgrade.sh --node m1 --node m2 --node m3 --node m4 \
#                        --archive ~/qadena-full-1.1.14-abc1234.tar.gz \
#                        --unique unique052 --signer <signerid>
#
# OPTIONS
#
#   --node HOST        A node to upgrade.  REPEATABLE, and THE ORDER IS THE ROLL ORDER.  The FIRST
#                      one is also the control node: it submits the governance proposal, it is the
#                      one restarted to force the promotion, and it is the node every status query
#                      is put to.  Any ssh-able name works (a ~/.ssh/config host, user@ip).
#                      BatchMode is on, so key auth must already work -- there is nowhere to type
#                      a passphrase.
#   --archive PATH     LOCAL path to a .tar.gz that ALREADY EXISTS.  See THE ARCHIVE below.
#                      Alternative to --build-from; exactly one of the two is required.
#   --build-from HOST  BUILD the release here first, then package it, fetch it, and roll it --
#                      one command from a committed tree to an upgraded fleet.  Builds with
#                      --hold (the live node keeps running) and VERIFIES that it held.  Reads
#                      --unique/--signer out of the resulting package, so neither needs typing.
#                      Builds EXACTLY what is committed: no --update-test-unique-id, no version
#                      bump, no edit to the tree.  See BUILDING WITH --build-from below.
#   --repo DIR         checkout directory under the build host's $HOME.  Default "qv3".
#   --build-sgx        force an SGX (reproducible docker) build, ~24 minutes.
#   --no-sgx           force a debug build on a host that HAS ego.  SGX is the default whenever
#                      ego is installed, and that choice sets -tags realenclave -- which decides
#                      whether real attestation is verified.  Be explicit on a mixed fleet.
#   --package-out DIR  where to stage the package on the build host.  Default /tmp/pkg.
#   --build-wait N     seconds to allow the build.  Default 3600.
#   --allow-dirty      permit a build from a tree with uncommitted changes.  Off by default:
#                      the artefact would match no commit, and nobody could later say what was
#                      deployed.
#   --quiesce-immediate  as --quiesce, but END the in-flight run NOW rather than waiting it out.
#                      SIGTERM first so a test's trap can resume an enclave it SIGSTOPped, then
#                      SIGKILL, then SIGCONT anything still stopped -- without that last step this
#                      option would manufacture the wedge it exists to prevent.
#   --quiesce          stop the continuous-regression loop on every node (and on the build host)
#                      and WAIT for any in-flight run to finish, before anything else happens.
#                      Without it the roll only WARNS.  Worth using: the regression restarts the
#                      node it runs on, which during a roll is a second node down.
#   --chain-only       roll a CHAIN-ONLY change: qadenad moved, the enclave did not.  Implies
#                      --skip-governance (an unchanged measurement is already registered).
#                      Packages --only chain,libs,scripts,config, so the unchanged enclave is
#                      not re-staged -- the build is not reproducible, so re-packaging an
#                      identical-in-name enclave would collide with the one already installed.
#                      Requires cmd/qadenad/version.txt to have moved, for the same reason.
#                      The enclave preconditions (strictly-greater version, measurement not
#                      already running) are SKIPPED, not because they are inconvenient but
#                      because they assert a handover this roll deliberately does not perform.
#   --unique ID        The NEW enclave measurement (unique052, or an SGX MRENCLAVE).  Required
#                      unless --skip-governance.  See WHERE --unique AND --signer COME FROM.
#   --signer ID        The enclave signer id.  Same condition.
#   --wait-secs N      How long to wait for the identity to go active, and what is passed to
#                      install_release.sh --wait-active on each node.  Default 1800.
#   --skip-governance  The measurement is ALREADY registered and ACTIVE.  Skips step 2 whole: no
#                      proposal, no votes, no promotion restart.  --unique/--signer not needed.
#   --dry-run          Print what would run.  No copy, no vote, no install.  Preflight and the
#                      advancing checks still run FOR REAL, so it needs a live fleet to work.
#   --help
#
# USE THIS WHEN THE RELEASE IS ENCLAVE-ONLY -- no new chain message type, no change to how a block
# is validated.  Then old and new nodes speak the same protocol, a mixed fleet is fine at every
# instant, and the nodes can simply be replaced in turn.
#
# USE split_roll_upgrade.sh INSTEAD IF THE RELEASE ADDS A CHAIN MESSAGE TYPE.  An old qadenad cannot
# decode one it was not built with, so a block carrying it is invalid to that node -- it halts or
# forks.  That case needs the chain binaries everywhere BEFORE any enclave that produces the new
# message goes live, which is a different (two-phase) shape.  If you are unsure which you have:
# did x/qadena/types/tx.proto gain a message?  Then it is the split roll.
#
# ---------------------------------------------------------------------------------------------
# THE ARCHIVE: WHERE IT COMES FROM AND HOW IT WAS MADE
# ---------------------------------------------------------------------------------------------
#
# This script does NOT build and does NOT package.  It consumes one artifact that already exists.
# That artifact is made on ONE machine, in two steps, and then distributed unchanged:
#
#   1. BUILD -- on one node only:
#
#          ./buildscripts/build.sh --hold [--no-sgx]
#
#      --hold stages the new binaries WITHOUT replacing the live ones (and without stopping the
#      node).  On SGX that is the only correct order, because the measurement is not knowable
#      until after the build has run.
#      --no-sgx is the opt-OUT, for a machine that HAS ego but wants debug artifacts.  SGX is the
#      DEFAULT whenever ego is installed, and that choice sets -tags realenclave, which silently
#      decides whether real attestation is verified.  Do not leave it to chance on a mixed fleet.
#
#      BUILD WHAT IS CHECKED IN.  The measurement being rolled is whatever the checkout says:
#      cmd/qadenad_enclave/test_unique_id.txt on a debug build, and on SGX the MRENCLAVE the build
#      computes, which moves with the code and needs no flag.  Do NOT pass --update-test-unique-id
#      here: it EDITS test_unique_id.txt in the tree, so the artifact stops matching the commit and
#      nobody can afterwards say what was deployed.  Same for cmd/qadenad_enclave/version.txt --
#      it is committed, not minted at deploy time.  A deploy rolls out a commit; it does not
#      author one.
#
#      Both values still have to be RIGHT before you start, and both fail LATE if they are not:
#        - version.txt must be STRICTLY GREATER than the version of the enclave currently holding
#          sealed params.  Otherwise the old enclave will not release its sealed keys, the swap
#          does not run, and it fails on the FIRST node -- after governance has already passed,
#          which is the expensive half to redo.
#        - test_unique_id.txt equal to what is already running means the chain cannot tell old code
#          from new, and the upgrade is a no-op that reports success.
#      Fix either one in the CHECKOUT and commit it.  scripts/enclave_identities.sh reads the tree
#      against the chain and says which of active / unvalidated / inactive / unregistered you are
#      in, and what it implies.
#
#   2. PACKAGE -- on that same machine:
#
#          ./buildscripts/package_release.sh [--out DIR]
#
#      Writes ./qadena-full-<version>-<commit>.tar.gz (--out puts it elsewhere; default is the
#      current directory).  It packages exactly what buildscripts/install.sh puts on a node --
#      chain binary, both enclaves, libwasmvm, scripts, config -- and NOTHING node-specific:
#      no genesis.json, no keyring, no sealed enclave_params_<id>.json.
#      --changed-since <manifest.txt> writes a qadena-update-... archive holding only the
#      components whose checksums actually moved, so an enclave-only fix does not push a 210MB
#      chain binary to four nodes.
#
#   3. Point --archive at that file.  Step 1 below scps it to every node and compares sha256
#      there before anything is installed.
#
# BUILD ON EXACTLY ONE MACHINE, AND DISTRIBUTE THE ONE ARTIFACT.  The build is NOT reproducible:
# backlog 105 records three builds of a single commit producing three different binaries.  A debug
# enclave takes its identity from an embedded text file, so N separately-built binaries all report
# the same `uniqueNNN` while being different code -- the registry says one measurement is active
# and several distinct binaries answer to it.  That is precisely the property MRENCLAVE exists to
# deny.  (package_release.sh's own header still asserts the build IS reproducible.  Backlog 105 is
# the measured result and the operator caught this in the field -- believe 105.)
#
# WHERE --unique AND --signer COME FROM
#
# package_release.sh reads them out of the enclave it just packaged and prints the registration
# line verbatim when it finishes:
#
#     If this enclave is NEW to the chain, register it before installing anywhere:
#       testscripts/test_update_enclave_identity.sh unique052 <signerid> unvalidated
#
# Those two values are --unique and --signer.  They are also written into the archive's own
# manifest.txt, which is where to read them later, when that terminal is long gone:
#
#     tar xzOf <archive> '*/manifest.txt' | grep qadenad_enclave
#
# Use --skip-governance INSTEAD of both when the measurement is already active.  Getting that
# wrong is only safe in one direction: --skip-governance against an UNregistered measurement
# leaves every node waiting out the full --wait-secs for an identity that never goes active.
#
# BUILDING WITH --build-from
#
# Everything in THE ARCHIVE above, done for you, on ONE host, in this order:
#
#   read version.txt and test_unique_id.txt   <- the checkout is the authority; never written
#   refuse on a dirty tree                     (unless --allow-dirty)
#   refuse if version.txt is not STRICTLY GREATER than what that host runs
#   refuse if the measurement is INACTIVE on chain (that is permanent) or already running
#   record sha256 of the live qadenad_enclave
#   build.sh --hold [--build-sgx|--no-sgx]
#   VERIFY --hold held: live binary byte-identical, node still answering, measurement unmoved
#   package_release.sh --out <--package-out>
#   fetch the tarball to the workstation, read --unique/--signer from its manifest.txt
#
# THE REFUSALS ARE THE POINT.  Every one of them is a failure that otherwise surfaces LATE: a
# version that is not strictly greater fails at the handover on the FIRST node, after governance
# has already passed; an inactive measurement can never be revived; a measurement equal to the
# running one makes the whole roll a no-op that reports success.  All three are knowable before
# anything is built, and none of them are this script's to FIX -- they are facts about the
# checkout, corrected there and committed.
#
# THE --hold VERIFICATION IS NOT PARANOIA.  Backlog 97: --hold is not threaded into the Docker
# invocation, and an in-container install.sh once reached out of the build container and stopped
# the host's chain at height 98145 -- during a --hold build whose entire purpose was to touch
# nothing.  The specific cause is guarded now, but the flag still disagrees between the outer and
# inner build, so this checks the OUTCOME rather than trusting the flag arrived.
#
# ---------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------
# THE ORDER MATTERS AND IS NOT OBVIOUS:
#
#   1. REGISTER the new measurement by governance, and get it PROMOTED to active, BEFORE touching
#      any node.  install_release.sh only cuts over to an ACTIVE identity; with --wait-active it
#      waits, but it cannot create the promotion.
#   2. QUORUM IS NOT ONE VOTE.  Governance quorum here is 33.4% and four equal validators are 25%
#      each, so a proposal voted by the submitter alone is REJECTED for want of quorum, with a
#      tally showing zero NO votes -- which reads as a rejection on merit and is not.  At least two
#      validators must vote.  This script votes from every node it is given.
#   3. PROMOTION IS TRIGGERED BY A RESTART, BUT ONLY AFTER THE PROPOSAL HAS PASSED.
#      validateEnclaveIdentities runs when unvalidatedEnclaveIdentitiesCheckCounter hits zero; it
#      starts at 1, so the first UpdateHeight after a restart runs it, and otherwise it is up to
#      keyUpdateFrequency ticks away.  So one node is restarted (on its OLD enclave -- harmless,
#      nothing is installed yet) to make the promotion happen now instead of hours from now.
#      The ORDER within this step matters as much as the step itself: the identity row that check
#      promotes does not EXIST until the proposal passes, so restarting first spends the trigger
#      on nothing and the promotion falls back to the next natural tick -- the very delay the
#      restart was for.  So: vote, wait for PROPOSAL_STATUS_PASSED, then restart.  Waiting also
#      makes the votes safe by construction, since a proposal cannot pass on votes still sitting
#      in a mempool that a restart would discard.
#   4. ONE NODE AT A TIME, and the next is not touched until this one is ADVANCING AND CAUGHT UP.
#      Processes being up is not health: on four equal validators one down leaves 75% and the chain
#      moves, two down leaves 50% and it halts with every process still running.  A node that is
#      BEHIND when a measurement is promoted can never trust it (backlog 99), which is why this
#      waits rather than pipelining.
#      A RISING HEIGHT ALONE IS NOT ENOUGH, and that distinction is the whole point: a node
#      replaying after its restart advances FASTER than a live one while contributing nothing to
#      quorum.  Height-only, the roll would take the next node down believing this one was back,
#      and reach 50% through the check meant to prevent it.  catching_up==false is what separates
#      "ingesting blocks" from "back in consensus".
#
# ALSO: install_release.sh refuses to overwrite a versioned binary whose bytes differ, and the
# signer enclave keeps its name across a non-reproducible rebuild -- so signer_enclave.<unique> is
# moved aside before installing.  It is MOVED, never deleted: the old enclave has to stay on disk
# for the --upgrade-mode handover.
#
# EXAMPLES
#
#   # The usual case: a new enclave, not yet known to the chain.
#   ./rolling_upgrade.sh --node m1 --node m2 --node m3 --node m4 \
#       --archive ~/qadena-full-1.1.14-abc1234.tar.gz \
#       --unique unique052 --signer 0d4a1f...
#
#   # One command, from a committed tree to an upgraded fleet.  m1 builds; all four roll.
#   ./rolling_upgrade.sh --node m1 --node m2 --node m3 --node m4 --build-from m1 --no-sgx
#
#   # Read the plan back before committing to it.
#   ./rolling_upgrade.sh --node m1 --node m2 --node m3 --node m4 \
#       --archive ~/qadena-full-1.1.14-abc1234.tar.gz \
#       --unique unique052 --signer 0d4a1f... --dry-run
#
#   # Resume a roll that died after m2 -- unique052 is already active, so governance is done.
#   # List only the nodes still to roll.  NOTE the quorum arithmetic still counts the WHOLE
#   # fleet, not just the nodes named here; the advancing check only watches the ones named.
#   ./rolling_upgrade.sh --node m3 --node m4 \
#       --archive ~/qadena-full-1.1.14-abc1234.tar.gz --skip-governance
#
# AFTERWARDS, the last line this prints is the one worth acting on.  The next rotation tick runs
# the SS re-share audit, and that is where a fleet which upgraded cleanly but can no longer
# re-share its interval keys says so:
#
#     grep 'ss-reshare: AUDIT' ~/qadena/logs/qadena.log

set -u
setopt ERR_EXIT PIPE_FAIL

NODES=(); ARCHIVE=""; NEW_UNIQUE=""; NEW_SIGNER=""; WAIT_SECS=1800; DRY=0; SKIP_GOV=0; VIA_GOV=0
BUILD_FROM=""; REPO_DIR="qv3"; SGX_MODE="auto"; PKG_OUT="/tmp/pkg"; BUILD_WAIT=3600; ALLOW_DIRTY=0
CHAIN_ONLY=0; QUIESCE=0; QUIESCE_NOW=0
BUILD_PATH='export PATH=/usr/local/go/bin:$HOME/go/bin:$PATH;'

while (( $# )); do
    case "$1" in
        --node)       NODES+=("$2"); shift 2 ;;
        --archive)    ARCHIVE="$2"; shift 2 ;;
        --unique)     NEW_UNIQUE="$2"; shift 2 ;;
        --signer)     NEW_SIGNER="$2"; shift 2 ;;
        --wait-secs)  WAIT_SECS="$2"; shift 2 ;;
        --skip-governance) SKIP_GOV=1; shift ;;   # already registered and active
        --build-from) BUILD_FROM="$2"; shift 2 ;;
        --repo)       REPO_DIR="$2"; shift 2 ;;
        --build-sgx)  SGX_MODE="sgx"; shift ;;
        --no-sgx)     SGX_MODE="nosgx"; shift ;;
        --package-out) PKG_OUT="$2"; shift 2 ;;
        --build-wait) BUILD_WAIT="$2"; shift 2 ;;
        --allow-dirty) ALLOW_DIRTY=1; shift ;;
        --chain-only)  CHAIN_ONLY=1; SKIP_GOV=1; shift ;;
        --via-governance) VIA_GOV=1; shift ;;
        --quiesce)     QUIESCE=1; shift ;;
        --quiesce-immediate) QUIESCE=1; QUIESCE_NOW=1; shift ;;
        --dry-run)    DRY=1; shift ;;
        # Print the whole leading comment block, however long it grows -- start at line 2 and
        # quit at the first line that is not a comment.  A fixed range silently truncates the
        # help the moment anyone adds a paragraph to it, which is how it came to end mid-sentence.
        --help|-h)    sed -n '2,${/^#/!q;p;}' "$0"; exit 0 ;;
        *) print -u2 "FAIL: unknown flag $1"; exit 1 ;;
    esac
done

(( ${#NODES} >= 1 )) || { print -u2 "FAIL: --node is required (repeatable)"; exit 1 }
[[ -n "$ARCHIVE" || -n "$BUILD_FROM" ]] \
    || { print -u2 "FAIL: one of --archive or --build-from is required"; exit 1 }
[[ -z "$ARCHIVE" || -z "$BUILD_FROM" ]] \
    || { print -u2 "FAIL: --archive and --build-from are alternatives; --build-from PRODUCES the archive"; exit 1 }

say()  { print -- "$(date '+%H:%M:%S')  $*" }
step() { print ""; print -- "=== $* ===" }
die()  { print -u2 "FAIL: $*"; exit 1 }
rsh()  { local h="$1"; shift; ssh -o ConnectTimeout=10 -o BatchMode=yes "$h" "bash -lc $(printf '%q' "$*")" }
run()  { local h="$1"; shift; if (( DRY )); then print -- "    [dry-run] $h: $*"; else rsh "$h" "$@"; fi }

height_of() { rsh "$1" '~/qadena/bin/qadenad status 2>/dev/null' 2>/dev/null \
                | tr ',' '\n' | grep -oE '"latest_block_height":"[0-9]+"' | grep -oE '[0-9]+' | head -1 }
# The node's own answer to "am I at the tip".  Separate from height_of because a rising height and
# being caught up are DIFFERENT CLAIMS, and conflating them is what require_advancing got wrong.
catching_up_of() { rsh "$1" '~/qadena/bin/qadenad status 2>/dev/null' 2>/dev/null \
                | tr ',' '\n' | grep -oE '"catching_up":(true|false)' | grep -oE '(true|false)' | head -1 }
measure_of() { rsh "$1" '~/qadena/bin/qadenad q qadena enclave-measurement -o json 2>/dev/null' 2>/dev/null \
                | grep -oE 'unique[0-9]+' | head -1 }
identity_status() { rsh "${NODES[1]}" "~/qadena/bin/qadenad q qadena show-enclave-identity $1 -o json 2>/dev/null" 2>/dev/null \
                | grep -oE '"status":"[a-z]+"' | head -1 | cut -d'"' -f4 }

# restart_node -- stop, WAIT FOR THE STOP TO DRAIN, start, and verify it actually came back.
#
# `sleep 5` between the two is not enough and the failure is silent in the worst way.
# stop_qadena.sh returns before the process group is gone; start_qadena.sh then sees the remnant,
# prints "Qadena is already running" and does NOTHING; the old process finishes exiting a moment
# later; and the node is left DOWN with nothing started and a success-looking log.  That cost M1
# twice on 2026-08-23 -- once here and once during a build -- and both times the chain kept moving
# on the other three, so nothing complained.
#
# So: poll until the processes are actually gone, then start, then poll until the node answers.
# A restart that does not come back is a hard failure, not something to discover three steps later.
restart_node() {
    local h="$1" i n
    rsh "$h" '~/qadena/scripts/stop_qadena.sh --all' >/dev/null 2>&1 || true

    # WAIT WITH THE SAME PREDICATE start_qadena.sh USES.  This used to poll `pgrep -c qadenad`,
    # which does NOT match signer_enclave -- while is_qadena_running (scripts/setup_env.sh) checks
    # FIVE patterns, signer_enclave among them.  So the guard could see "nothing running", start
    # the node, and start_qadena.sh would spot a lingering signer_enclave, print "Qadena is
    # already running" and DO NOTHING.  The straggler exits a moment later and the node is left
    # DOWN behind a log that reads like success.
    #
    # That is precisely the failure this function exists to prevent -- it simply arrived through a
    # process the old predicate did not watch.  It cost a full roll on 2026-08-24: M1 was stopped
    # for the promotion restart, never came back, and the run failed two steps later.
    #
    # Keep this list in sync with is_qadena_running.  A narrower probe here is not a small
    # optimisation; it is this bug.
    local probe='pgrep -x qadenad >/dev/null || pgrep -x qadenad_enclave >/dev/null || pgrep -f "[e]go-host.*qadenad_enclave" >/dev/null || pgrep -f "[e]go-host.*signer_enclave" >/dev/null || pgrep -x signer_enclave >/dev/null'
    local alive=1
    for i in $(seq 1 40); do
        if rsh "$h" "$probe" >/dev/null 2>&1; then
            alive=1; sleep 3
        else
            alive=0; break
        fi
    done
    (( alive == 0 )) \
        || die "$h: a qadena process is still alive after stop_qadena.sh --all (qadenad, qadenad_enclave, signer_enclave or an ego-host child); refusing to start a second one"

    # Detached, and with a command line that does NOT contain the words is_qadena_running greps
    # for -- see scripts/setup_env.sh, where an -f pattern matching the caller made this report
    # "already running" against a stopped node.
    ssh -f -o BatchMode=yes "$h" 'nohup ~/qadena/scripts/start_qadena.sh >/tmp/rolling_start.log 2>&1 &' || true
    for i in $(seq 1 25); do
        [[ -n "$(height_of "$h")" ]] && { say "  $h restarted, answering"; return 0 }
        sleep 10
    done
    # SAY WHICH FAILURE IT WAS.  "Did not come back" covers two very different things, and the
    # operator should not have to go read the log to tell them apart: a node that started and is
    # still catching up, versus a start that NO-OPPED because something looked like a running
    # node.  The second prints "already running" and is the one that wastes the whole window.
    if rsh "$h" 'grep -q "already running" /tmp/rolling_start.log' 2>/dev/null; then
        die "$h: start_qadena.sh NO-OPPED -- it printed \"Qadena is already running\" against a node that is down, so a qadena process was still lingering when it ran.  Nothing was started.  See the probe in restart_node."
    fi
    die "$h did not come back after a restart -- check /tmp/rolling_start.log on it"
}

# quiesce_node stops a node's continuous-regression loop and waits for any in-flight run to end.
#
# Copied from nth_node_bringup.sh's --quiesce, for a reason that applies MORE here than there: the
# regression's enclave-rollback, enclave-crash and enclave-upgrade suites STOP AND RESTART the node
# they run on.  During a roll that is a second node down while this script already has one down --
# on five validators that can cross the 1/3 line and halt the chain, which is backlog 108.
#
# And enclave-crash is worse than merely disruptive right now: it leaves the node WEDGED roughly one
# time in twelve (2026-08-25, M1 stuck on one block for 4h11m).  A wedged node mid-roll fails
# require_advancing and aborts the run with the fleet half-upgraded.
#
# TWO STEPS, IN THIS ORDER.  Kill the LOOP first so it cannot start another run, then wait for the
# run already in flight -- killing that one mid-suite is what leaves an enclave SIGSTOPped with
# nothing left alive to SIGCONT it.
quiesce_node() {
    local h="$1" pids p n i stopped
    pids=$(rsh "$h" 'pgrep -f "[r]un_regression_continually" 2>/dev/null; true' | tr -d '\r' | tr '\n' ' ') || true
    # --dry-run MUST NOT KILL ANYTHING.  Preflight's read-only checks run for real under --dry-run
    # because looking costs nothing, but stopping an operator's regression loop is a change to the
    # fleet -- and a dry run that has side effects is not a dry run.  Say what would happen instead.
    if (( DRY )); then
        if [[ -n "${pids// /}" ]]; then
            print -- "    [dry-run] $h: would stop the regression loop (pids: ${pids% })$( (( QUIESCE_NOW )) && print -n ' and END the in-flight run immediately' || print -n ' and wait for the in-flight run')"
        else
            print -- "    [dry-run] $h: no regression loop running"
        fi
        return 0
    fi
    if [[ -n "${pids// /}" ]]; then
        say "  $h: stopping the continuous-regression loop (pids: ${pids% })"
        for p in ${=pids}; do rsh "$h" "kill $p" >/dev/null 2>&1 || true; done
        sleep 3
    fi
    if (( QUIESCE_NOW )); then
        # --quiesce-immediate: end the run in flight rather than waiting it out.
        #
        # SIGTERM FIRST, AND NOT OUT OF POLITENESS.  test_enclave_crash_recovery.sh SIGSTOPs the
        # enclave and resumes it from a `trap ... EXIT INT TERM`.  SIGTERM lets that trap run, so
        # the test resumes the enclave itself.  SIGKILL skips it and strands a STOPPED enclave with
        # the node frozen behind it -- manufacturing the very wedge this option exists to avoid.
        say "  $h: ending the in-flight regression run now (SIGTERM, then SIGKILL)"
        rsh "$h" 'pkill -TERM -f "[r]egression.sh" 2>/dev/null; true' >/dev/null 2>&1 || true
        for i in $(seq 1 10); do
            n=$(rsh "$h" 'pgrep -cf "[r]egression.sh" 2>/dev/null; true' 2>/dev/null | tr -d '\r' | head -1)
            [[ "${n:-0}" -eq 0 ]] && break
            sleep 2
        done
        if [[ "${n:-0}" -ne 0 ]]; then
            say "  $h: did not exit on SIGTERM; SIGKILL"
            rsh "$h" 'pkill -KILL -f "[r]egression.sh" 2>/dev/null; true' >/dev/null 2>&1 || true
            sleep 2
        fi
        # THE BACKSTOP that makes this option safe to offer at all.  If the trap did not run --
        # SIGKILL, or a suite that never installed one -- the enclave is still SIGSTOPped and the
        # node is frozen behind a healthy-looking process table.  Resume anything stopped; a
        # SIGCONT to a process that was never stopped costs nothing.
        stopped=$(rsh "$h" 'ps -eo stat=,pid=,comm= 2>/dev/null | awk "\$1 ~ /^T/ && \$3 ~ /qadenad|enclave/ {print \$2}" | tr "\n" " "; true' 2>/dev/null | tr -d '\r')
        if [[ -n "${stopped// /}" ]]; then
            say "  $h: resuming STOPPED enclave process(es): ${stopped% }  (a killed test left them halted)"
            rsh "$h" "kill -CONT ${stopped}" >/dev/null 2>&1 || true
        fi
        return 0
    fi

    # `pgrep -c` PRINTS the count AND EXITS NON-ZERO when it is zero, so the obvious `|| echo 0`
    # appends a SECOND line and the arithmetic below sees "0\n0".  Same trap this repo has now
    # recorded three times; `; true` plus head -1 is the fix.
    for i in $(seq 1 120); do
        n=$(rsh "$h" 'pgrep -cf "[r]egression.sh" 2>/dev/null; true' 2>/dev/null | tr -d '\r' | head -1)
        [[ "${n:-0}" -eq 0 ]] && break
        (( i == 1 )) && say "  $h: waiting for the in-flight regression run to finish"
        sleep 30
    done
    [[ "${n:-0}" -eq 0 ]] || die "$h: regression still running after an hour -- stop it before rolling"
}

require_advancing() {
    local h1 h2 cu
    h1=$(height_of "$1") || true; [[ -n "$h1" ]] || die "$1: no height -- is qadenad running?"
    sleep 12
    h2=$(height_of "$1") || true; [[ -n "$h2" ]] || die "$1: stopped answering"
    (( h2 > h1 )) || die "$1: height stuck at $h1 -- chain not advancing, refusing to continue"

    # A RISING HEIGHT IS NOT PARTICIPATION.  A node REPLAYING after a restart advances faster than
    # a live one, while contributing nothing to quorum -- so it sails through the height check and
    # the roll takes the next node down believing this one is back.  On four validators that is
    # exactly how a rolling upgrade arrives at 50% and halts (backlog 108), through the very check
    # written to prevent it.
    #
    # catching_up is the node's own answer to "am I at the tip", and it is the difference between
    # "ingesting blocks" and "back in consensus".  Checked AFTER the height test so the two failures
    # report separately: a stuck height and a replaying node are different problems.
    cu=$(catching_up_of "$1") || true
    [[ "$cu" == "false" ]] \
        || die "$1: catching_up=${cu:-unknown} -- it is REPLAYING, not participating in consensus.  Its height rises but it adds nothing to quorum, so taking the next node down now is how the chain halts."
    say "  $1 advancing $h1 -> $h2 (caught up)"
}

step "0. preflight"
# COSMOVISOR: the per-node install_release --restart in step 3 is a LIVE binary swap with no
# governance plan -- the unmanaged mechanism.  Managed nodes refuse it at install time anyway;
# refuse here first, before anything is stopped.  (--via-governance, which stages instead, will
# bypass this check when it lands.)
for __n in "${NODES[@]}"; do
    if (( VIA_GOV )); then
        run "$__n" 'test -L $HOME/qadena/cosmovisor/current' 2>/dev/null \
            || die "$__n is NOT cosmovisor-managed -- --via-governance stages binaries for a swap that only cosmovisor performs.  Run cosmovisor_setup.sh there first."
        run "$__n" 'test -x $HOME/qadena/bin/cosmovisor' 2>/dev/null \
            || die "$__n has no cosmovisor binary"
    else
        if run "$__n" 'test -L $HOME/qadena/cosmovisor/current' 2>/dev/null; then
            die "$__n is cosmovisor-managed.  This roll swaps live binaries outside a governance plan; use --via-governance (or de-convert the node deliberately)."
        fi
    fi
done
for n in "${NODES[@]}"; do
    rsh "$n" 'true' || die "$n unreachable"
    say "$n  enclave=$(measure_of $n)  height=$(height_of $n)"
done
# QUIESCE BEFORE ASSERTING HEALTH, not after: a node that regression has just stopped would fail
# require_advancing below and abort the roll for a reason that is about the test suite rather than
# the fleet.  The build host is included even when it is not being rolled -- it is where the build
# runs, and a regression restarting it mid-build is its own failure.
quiesce_targets=("${NODES[@]}")
if [[ -n "$BUILD_FROM" ]] && ! (( ${NODES[(Ie)$BUILD_FROM]} )); then
    quiesce_targets+=("$BUILD_FROM")
fi
if (( QUIESCE )); then
    say ""
    say "--quiesce: stopping continuous regression on ${#quiesce_targets} node(s)"
    for n in "${quiesce_targets[@]}"; do quiesce_node "$n"; done
    say "  quiescent"
else
    # REPORT, do not refuse.  The operator may know something this script does not -- a --skip list
    # that drops the chain-restarting suites, or a run that is nearly done.  Refusing outright would
    # be wrong; staying quiet about it is how last night's roll needed a manual step nobody recorded.
    for n in "${quiesce_targets[@]}"; do
        rn=$(rsh "$n" 'pgrep -cf "[r]egression" 2>/dev/null; true' 2>/dev/null | tr -d '\r' | head -1)
        if [[ "${rn:-0}" -ne 0 ]]; then
            say "  WARNING: $n is running regression ($rn process(es))"
            say "           enclave-rollback, enclave-crash and enclave-upgrade STOP AND RESTART the"
            say "           node they run on.  A second node down while this roll has one down can"
            say "           halt the chain (backlog 108), and enclave-crash leaves it wedged about"
            say "           one time in twelve.  Re-run with --quiesce, or --skip those suites."
        fi
    done
fi

for n in "${NODES[@]}"; do require_advancing "$n"; done

# With --build-from there is no archive yet -- 0b creates it and sets ARCHIVE.  Checked there.
if [[ -z "$BUILD_FROM" ]]; then
    [[ -f "$ARCHIVE" ]] || die "archive not found: $ARCHIVE"
fi

# ---------------------------------------------------------------------------------------------
# 0b. BUILD AND PACKAGE.  Optional (--build-from); without it an --archive is supplied ready-made.
#
# THIS BUILDS WHAT IS CHECKED IN, AND NOTHING ELSE.  No --update-test-unique-id, no version bump,
# no edit of any kind to the tree on the build host.  A deploy rolls out a commit; it does not
# author one.  If the measurement or the version is wrong for this roll, that is a fact about the
# CHECKOUT -- it is fixed there and committed, and this script's job is to refuse and say so.
#
# It builds on exactly ONE host and distributes that one artifact, which is the rule backlog 105
# exists to enforce: the build is not reproducible, and a debug enclave takes its identity from an
# embedded label, so N separately-built binaries all answer to the same uniqueNNN while being
# different code.  Automating it here is how that rule stops depending on everyone remembering it.
if [[ -n "$BUILD_FROM" ]]; then
    step "0b. build and package on $BUILD_FROM (--hold: the live node keeps running)"
    RD="\$HOME/$REPO_DIR"

    # WHAT THE CHECKOUT SAYS.  Read, never written.  On SGX test_unique_id.txt does not describe
    # the artefact at all (MRENCLAVE does, and it is not knowable until after the build), so an
    # empty value here is normal and not an error.
    SRC_VER=$(rsh "$BUILD_FROM" "cat $RD/cmd/qadenad_enclave/version.txt 2>/dev/null" | tr -d '\r' | head -1) || true
    SRC_UNIQ=$(rsh "$BUILD_FROM" "cat $RD/cmd/qadenad_enclave/test_unique_id.txt 2>/dev/null" | tr -d '\r' | head -1) || true
    [[ -n "$SRC_VER" ]] || die "$BUILD_FROM: no cmd/qadenad_enclave/version.txt under $RD -- is --repo right?"
    say "checkout: version=$SRC_VER unique=${SRC_UNIQ:-(sgx: computed by the build)}"

    # A DIRTY TREE BREAKS THE PREMISE.  "What is checked in is what gets rolled out" is only true
    # if the tree IS what is checked in; otherwise the artefact matches no commit and afterwards
    # nobody can say what was deployed.  --allow-dirty for a deliberate one-off.
    DIRTY=$(rsh "$BUILD_FROM" "cd $RD && git status --porcelain 2>/dev/null | head -20") || true
    if [[ -n "$DIRTY" ]]; then
        print "$DIRTY" | while read -r l; do say "    $l"; done
        (( ALLOW_DIRTY )) || die "$BUILD_FROM:$RD has uncommitted changes -- commit them, or pass --allow-dirty to roll a tree that matches no commit"
        say "  proceeding on a DIRTY tree (--allow-dirty); the artefact matches no commit"
    fi
    SRC_COMMIT=$(rsh "$BUILD_FROM" "cd $RD && git rev-parse --short HEAD 2>/dev/null" | tr -d '\r') || true
    say "commit:   ${SRC_COMMIT:-unknown}"

    # PRECONDITION, AND IT FAILS LATE IF UNCHECKED: the handover needs a STRICTLY GREATER version.
    # The old enclave will not release its sealed keys otherwise and the swap simply does not run
    # -- on the FIRST node, after governance has already passed, which is the expensive half to
    # redo.  Checked here, before anything is built or proposed.
    LIVE_VER=$(rsh "$BUILD_FROM" '~/qadena/bin/qadenad_enclave -version 2>/dev/null' | tr -d '\r' | head -1) || true

    # THE CHAIN VERSION IS NO LONGER ONLY --chain-only's BUSINESS.  --via-governance derives the
    # PLAN NAME from it (v$SRC_CHAIN), so it is read unconditionally now.
    SRC_CHAIN=$(rsh "$BUILD_FROM" "cat $RD/cmd/qadenad/version.txt 2>/dev/null" | tr -d '\r' | head -1) || true
    LIVE_CHAIN=$(rsh "$BUILD_FROM" '~/qadena/bin/qadenad version 2>/dev/null' | tr -d '\r' | head -1) || true

    # IS THE ENCLAVE ACTUALLY PART OF THIS ROLL?  The three enclave preconditions below all
    # protect the HANDOVER, so applying them to a roll that changes no measurement asserts a
    # transition nobody is making -- which is exactly how a chain-only --via-governance run died
    # in stage E on 2026-08-26, demanding a bump to cmd/qadenad_enclave/version.txt for an enclave
    # it was not touching.  --chain-only says so explicitly; --via-governance is told by the
    # checkout: same measurement as the build host runs means enclave-unchanged.  The live roll
    # (neither flag) keeps asserting them exactly as before.
    # An enclave-unchanged --via-governance roll IS a chain-only roll in every downstream
    # respect -- skip the enclave build, package without it, register no identity -- so it SETS
    # CHAIN_ONLY rather than adding a second condition at each of those sites.  (SKIP_GOV is not
    # set with it: --chain-only sets that at parse time because a live roll has no proposal to
    # make, whereas this roll's whole purpose is one.)
    ENCL_CHANGING=1
    if (( CHAIN_ONLY )); then
        ENCL_CHANGING=0
    elif (( VIA_GOV )); then
        run_meas0=$(measure_of "$BUILD_FROM") || true
        if [[ -n "$SRC_UNIQ" && -n "$run_meas0" && "$SRC_UNIQ" == "$run_meas0" ]]; then
            ENCL_CHANGING=0
            CHAIN_ONLY=1
            say "enclave:  $SRC_UNIQ unchanged -- treating this as a chain-only upgrade"
        fi
    fi

    # The chain version must MOVE for any staged upgrade.  Two independent reasons, either fatal:
    # the plan name would otherwise name a version the running binary ALREADY registers a handler
    # for, so nothing would ever halt and the "upgrade" would silently no-op; and install_release
    # refuses to overwrite qadenad.<version> with the differing bytes of a non-reproducible build.
    if (( CHAIN_ONLY || VIA_GOV )); then
        [[ -n "$SRC_CHAIN" ]] || die "$BUILD_FROM: cannot read $RD/cmd/qadenad/version.txt"
        if [[ -n "$LIVE_CHAIN" && "$SRC_CHAIN" == "$LIVE_CHAIN" ]]; then
            die "cmd/qadenad/version.txt is $SRC_CHAIN and $BUILD_FROM already runs $SRC_CHAIN.  A plan named v$SRC_CHAIN would be one the RUNNING binary already has a handler for, so no node would ever halt for it and the swap would silently not happen.  Bump cmd/qadenad/version.txt in the checkout and COMMIT it."
        fi
        say "chain:    $LIVE_CHAIN -> $SRC_CHAIN$( (( VIA_GOV )) && print -n " (plan v$SRC_CHAIN)" )"
    fi

    if (( CHAIN_ONLY )); then
        # --chain-only: THE ENCLAVE IS DELIBERATELY UNCHANGED, so the two checks below are not
        # merely skippable, they are WRONG here.  Both exist to protect the enclave HANDOVER --
        # an unchanged measurement means no handover happens at all, so "the version must be
        # strictly greater" and "the measurement must differ from the running one" are asserting
        # a transition that this roll is specifically not making.  What must still be true is that
        # the CHAIN version moved, because install_release.sh refuses to overwrite a versioned
        # binary whose bytes differ, and a non-reproducible rebuild always differs.
        say "chain-only: enclave stays $SRC_VER/$SRC_UNIQ"
    elif (( ENCL_CHANGING )) && [[ -n "$LIVE_VER" && -n "$SRC_VER" ]]; then
        say "running:  version=$LIVE_VER"
        if [[ "$SRC_VER" == "$LIVE_VER" ]]; then
            die "version.txt is $SRC_VER and $BUILD_FROM already runs $SRC_VER -- the handover needs a STRICTLY GREATER version and will not run.  Bump cmd/qadenad_enclave/version.txt in the checkout and COMMIT it."
        fi
        newest=$(printf '%s\n%s\n' "$SRC_VER" "$LIVE_VER" | sort -V | tail -1)
        [[ "$newest" == "$SRC_VER" ]] \
            || die "version.txt is $SRC_VER but $BUILD_FROM runs $LIVE_VER, which is NEWER -- the handover needs a strictly greater version.  This checkout is behind."
    fi

    # A MEASUREMENT THE CHAIN HAS RETIRED IS RETIRED PERMANENTLY -- governance cannot move an
    # inactive row back.  Cheaper to learn now than after a proposal.
    if [[ -n "$SRC_UNIQ" ]] && (( ENCL_CHANGING )); then
        st=$(identity_status "$SRC_UNIQ") || true
        [[ "$st" == "inactive" ]] \
            && die "$SRC_UNIQ is INACTIVE on chain and that is PERMANENT -- pick a NEW measurement in the checkout (cmd/qadenad_enclave/test_unique_id.txt) and commit it"
        run_meas=$(measure_of "$BUILD_FROM") || true
        [[ -n "$run_meas" && "$run_meas" == "$SRC_UNIQ" ]] \
            && die "the checkout's measurement ($SRC_UNIQ) is already what $BUILD_FROM runs -- this roll would be a no-op that reports success.  Commit a new test_unique_id.txt."
        [[ -n "$st" ]] && say "chain:    $SRC_UNIQ is $st"
    fi

    # RECORD THE LIVE BINARY BEFORE BUILDING so --hold can be VERIFIED rather than trusted.  It has
    # been wrong before: backlog 97 records a --hold build whose in-container install.sh reached out
    # of the build container and stopped the host's chain, because --hold is not threaded into the
    # Docker invocation.  That is guarded now, but the flag still disagrees between outer and inner
    # build, so this asserts the outcome instead of assuming the flag arrived.
    PRE_SHA=$(rsh "$BUILD_FROM" 'sha256sum ~/qadena/bin/qadenad_enclave 2>/dev/null | cut -d" " -f1' | tr -d '\r') || true
    PRE_MEAS=$(measure_of "$BUILD_FROM") || true

    sgxflag=""
    case "$SGX_MODE" in
        sgx)   sgxflag=" --build-sgx" ;;
        nosgx) sgxflag=" --no-sgx" ;;
    esac
    # CHAIN-ONLY MUST NOT BUILD THE ENCLAVE.  Two independent reasons, and either alone is enough:
    #
    #   1. Nothing consumes it.  --chain-only packages --only chain,libs,scripts,config, so the
    #      enclave that gets built is discarded.  It is the largest compile-and-link in the build
    #      and its entire contribution to this roll is delay.
    #
    #   2. It is the step that keeps killing the node.  Both SEGVs this fleet has recorded -- 2 out
    #      of 62 node exits, 2026-08-24 20:27 and 2026-08-25 20:41 -- happened during a build, and
    #      both times the enclave build was the part that failed (silently, with no compiler output)
    #      while qadenad died with rc 139.  The other 60 exits were ordinary rc 1 stops.  This box
    #      has 2 cores and 3.9GB; the enclave link is the memory peak, and dropping it removes the
    #      largest contributor to whatever that interaction is.
    #
    # --hold does NOT do this: it is a staging flag, not a skip flag.  It is threaded THROUGH to
    # build_enclave.sh, whose `go build` is unconditional -- --hold only decides whether the result
    # replaces the live binary or is staged beside it.  --skip-enclave gates both build_enclave.sh
    # and build_signer_enclave.sh, while the chain install above that gate still runs.
    (( CHAIN_ONLY )) && sgxflag="$sgxflag --skip-enclave"

    LOCAL_PKG="${TMPDIR:-/tmp}/rolling_upgrade_pkg"
    mkdir -p "$LOCAL_PKG"
    BLOG="$LOCAL_PKG/build.log"

    if (( DRY )); then
        print -- "    [dry-run] $BUILD_FROM: cd $RD && ./buildscripts/build.sh --hold$sgxflag"
        print -- "    [dry-run] $BUILD_FROM: ./buildscripts/package_release.sh --out $PKG_OUT"
        print -- "    [dry-run] fetch the tarball and read --unique/--signer from its manifest"
    else
        # RUN THE BUILD ATTACHED.  This used to launch it detached (ssh -f + nohup, output to a
        # remote log) and then INFER the result: poll `pgrep` until the process was gone, then grep
        # that log for "SUCCESS!".  Both halves of that inference are unsound.
        #
        #   - The poll can fire before the build has even started.  `ssh -f` returns as soon as it
        #     backgrounds, but the remote still has to open a LOGIN shell and source its profile
        #     before build.sh exists as a process.  A pgrep in that window finds nothing and the
        #     loop concludes the build already finished.
        #   - Grepping for one string turns "did it work" into "did this line appear", and a build
        #     that dies without printing it is indistinguishable from a build that never ran.
        #   - Worst, the failure output had to be reconstructed afterwards with `tail -25`, so a
        #     compiler error further back was simply not visible.  A build that failed on
        #     2026-08-24 showed only its header and FINAL ERROR, with no cause, for this reason.
        #
        # Attached, ssh's exit status IS the build's exit status, and every line is streamed as it
        # is produced.  The remote command is deliberately NOT piped on the far side -- a remote
        # `| tee` would make ssh report TEE's status, which is 0 even when the build failed.  tee
        # runs here instead.  ServerAlive keeps a long SGX build from dying on an idle channel.
        say "building on $BUILD_FROM -- debug ~1 min, SGX ~24 min.  Output follows:"
        timeout "$BUILD_WAIT" ssh -o ConnectTimeout=10 -o BatchMode=yes \
                -o ServerAliveInterval=30 -o ServerAliveCountMax=20 "$BUILD_FROM" \
                "cd $RD && $BUILD_PATH ./buildscripts/build.sh --hold$sgxflag" 2>&1 \
            | tee "$BLOG" | while read -r l; do print -- "      $l"; done
        brc=${pipestatus[1]}
        (( brc == 124 )) && die "the build TIMED OUT after ${BUILD_WAIT}s on $BUILD_FROM (--build-wait to allow longer)"
        (( brc == 0 )) || die "the build FAILED on $BUILD_FROM (exit $brc) -- the full output is above and in $BLOG"
        say "  build succeeded"

        # --hold HELD?  The live binary must be byte-identical and the node must still be answering.
        POST_SHA=$(rsh "$BUILD_FROM" 'sha256sum ~/qadena/bin/qadenad_enclave 2>/dev/null | cut -d" " -f1' | tr -d '\r') || true
        if [[ -n "$PRE_SHA" && "$PRE_SHA" != "$POST_SHA" ]]; then
            die "--hold DID NOT HOLD: the live qadenad_enclave on $BUILD_FROM changed during the build ($PRE_SHA -> $POST_SHA).  The staged-only invariant is broken; do not roll this.  See backlog 97."
        fi
        [[ -n "$(height_of "$BUILD_FROM")" ]] \
            || die "--hold DID NOT HOLD: $BUILD_FROM stopped answering during the build -- something in it stopped the node (backlog 97)"
        POST_MEAS=$(measure_of "$BUILD_FROM") || true
        [[ -z "$PRE_MEAS" || "$PRE_MEAS" == "$POST_MEAS" ]] \
            || die "--hold DID NOT HOLD: live measurement moved $PRE_MEAS -> $POST_MEAS during the build"
        say "  --hold verified: live binary untouched, node still advancing"

        step "0c. package on $BUILD_FROM and fetch the artifact"
        rsh "$BUILD_FROM" "rm -rf $PKG_OUT && mkdir -p $PKG_OUT" || die "could not prepare $PKG_OUT on $BUILD_FROM"
        # PACKAGE ONLY WHAT CHANGED.  A full package re-stages qadenad_enclave.<unique> and
        # signer_enclave.<unique>; the build is not reproducible, so those bytes differ from the
        # ones already on every node, and install_release.sh refuses to overwrite a versioned
        # binary whose contents differ.  A chain-only roll would fail at the first install for a
        # component it never meant to touch.
        only_arg=""
        # Reached by --via-governance too, via the CHAIN_ONLY it sets when the measurement did not
        # move: shipping a REBUILT enclave carrying the same embedded measurement is backlog 105's
        # hazard (two different binaries answering to one uniqueNNN).  Left out, --stage-upgrade
        # carries the current generation's enclave forward byte-for-byte, which is what "the
        # enclave did not change" should mean.
        (( CHAIN_ONLY )) && only_arg=" --only chain,libs,scripts,config"
        out=$(rsh "$BUILD_FROM" "cd $RD && $BUILD_PATH ./buildscripts/package_release.sh --out $PKG_OUT$only_arg 2>&1 | tail -25") \
            || { print "$out" | while read -r l; do say "    $l"; done; die "package_release.sh failed on $BUILD_FROM" }
        print "$out" | while read -r l; do say "    $l"; done

        tgz=$(rsh "$BUILD_FROM" "ls -1 $PKG_OUT/*.tar.gz 2>/dev/null | head -1" | tr -d '\r') || true
        [[ -n "$tgz" ]] || die "package_release.sh produced no tarball in $BUILD_FROM:$PKG_OUT"

        # Pull it DOWN to the workstation: step 1 distributes from here, so that every node gets
        # the same bytes from one place and each copy is sha256-verified on arrival.
        ARCHIVE="$LOCAL_PKG/$(basename $tgz)"
        say "fetching $BUILD_FROM:$tgz"
        scp -q "$BUILD_FROM:$tgz" "$ARCHIVE" || die "could not fetch the package from $BUILD_FROM"
        say "  archive: $ARCHIVE"

        # --unique / --signer FROM THE ARTEFACT, not from the operator's memory.  These are the two
        # values a governance proposal is built from, and hand-copying them is how a roll ends up
        # waiting out the full --wait-secs for an identity that was never registered.
        man=$(tar xzOf "$ARCHIVE" '*/manifest.txt' 2>/dev/null) || true
        [[ -n "$man" ]] || die "the package has no manifest.txt -- cannot read the measurement out of it"
        # A chain-only package carries no enclave, so it carries no measurement -- and needs none:
        # --chain-only implies --skip-governance, because there is no new identity to register.
        if (( CHAIN_ONLY )); then
            say "  chain-only package: no enclave component, nothing to register"
        elif [[ -z "$NEW_UNIQUE" ]]; then
            NEW_UNIQUE=$(print -r -- "$man" | grep '^qadenad_enclave.unique_id:' | awk '{print $2}') || true
            [[ -n "$NEW_UNIQUE" ]] || die "manifest.txt carries no qadenad_enclave.unique_id"
            say "  measurement (from the manifest): $NEW_UNIQUE"
        else
            say "  measurement: $NEW_UNIQUE (given on the command line, overriding the manifest)"
        fi
        if [[ -z "$NEW_SIGNER" ]] && (( ! CHAIN_ONLY )); then
            NEW_SIGNER=$(print -r -- "$man" | grep '^qadenad_enclave.signer:' | awk '{print $2}') || true
            [[ -n "$NEW_SIGNER" ]] || die "manifest.txt carries no qadenad_enclave.signer"
            say "  signer      (from the manifest): $NEW_SIGNER"
        fi
    fi
fi

step "1. distribute (one artifact, verified by content on every node)"
# Under --dry-run with --build-from nothing was actually built, so there is no archive to hash.
# Say that plainly rather than dying: the point of the dry run is to show the PLAN.
if [[ -n "$ARCHIVE" ]]; then
    [[ -f "$ARCHIVE" ]] || die "archive not found: $ARCHIVE"
    LOCAL_SHA=$(shasum -a 256 "$ARCHIVE" | cut -d' ' -f1)
    say "archive sha256 $LOCAL_SHA"
    REMOTE="/tmp/$(basename $ARCHIVE)"
elif (( DRY )); then
    LOCAL_SHA="(dry-run: --build-from would have produced it)"
    REMOTE="/tmp/(the package built by 0c)"
    say "archive $LOCAL_SHA"
else
    die "no archive to distribute"
fi
for n in "${NODES[@]}"; do
    if (( DRY )); then print -- "    [dry-run] scp -> $n"; continue; fi
    scp -q "$ARCHIVE" "$n:$REMOTE" || die "$n: copy failed"
    got=$(rsh "$n" "sha256sum $REMOTE" | cut -d' ' -f1)
    [[ "$got" == "$LOCAL_SHA" ]] || die "$n: sha256 $got != $LOCAL_SHA"
    say "  $n verified"
done

# ---------------------------------------------------------------------------------------------
# --via-governance: everything up to here (preflight, build --hold, package, distribute) is
# identical to a live roll.  From here the shapes diverge completely: instead of a per-node
# install+restart, binaries are STAGED everywhere, ONE proposal schedules the swap, and the chain
# itself performs it at H on every node in the same block.  The whole point over the live roll:
# no window in which the fleet runs mixed versions, and the history stays replayable because the
# boundary is recorded on chain.
if (( VIA_GOV )); then
    [[ -n "$SRC_CHAIN" ]] || die "--via-governance needs --build-from (the plan name comes from the built version)"
    PLAN="v$SRC_CHAIN"
    step "2g. stage $PLAN on every node (nothing live is touched)"
    for n in "${NODES[@]}"; do
        ILOG="/tmp/stage_upgrade_$$.log"
        run "$n" "~/qadena/scripts/install_release.sh $REMOTE --stage-upgrade $PLAN > $ILOG 2>&1 < /dev/null" \
            || { run "$n" "tail -20 $ILOG" | sed 's/^/    /'; die "$n: staging failed (full log: $n:$ILOG)"; }
        say "  $n staged"
    done
    if (( ! DRY )); then
        # STAGED IS NOT ENOUGH -- STAGED THE SAME THING IS.  A node whose staged bytes differ
        # forks at H, and nothing before H would say so.
        ref_sha=""
        for n in "${NODES[@]}"; do
            sha=$(rsh "$n" "sha256sum ~/qadena/cosmovisor/upgrades/$PLAN/bin/qadenad 2>/dev/null" | cut -d' ' -f1)
            [[ -n "$sha" ]] || die "$n: no staged qadenad for $PLAN after staging reported success"
            [[ -z "$ref_sha" ]] && ref_sha="$sha"
            [[ "$sha" == "$ref_sha" ]] || die "$n: staged qadenad sha differs across the fleet ($sha != $ref_sha)"
        done
        say "  staged qadenad identical on ${#NODES} node(s): ${ref_sha:0:16}"
    fi

    step "2h. one proposal: schedule $PLAN$( [[ -n "$NEW_UNIQUE" ]] && print -n ", register $NEW_UNIQUE" )"
    encl_args=""
    live_uniq=$(measure_of "${NODES[1]}")
    if [[ -n "$NEW_UNIQUE" && "$NEW_UNIQUE" != "$live_uniq" ]]; then
        say "  enclave changes: $live_uniq -> $NEW_UNIQUE (identity message rides in the proposal)"
        encl_args="--unique-id $NEW_UNIQUE --signer-id $NEW_SIGNER"
    else
        say "  chain-only ($live_uniq unchanged): no identity message"
    fi
    run "${NODES[1]}" "~/qadena/scripts/gov_software_upgrade.sh --plan $PLAN --margin 180 $encl_args" \
        || die "the governance step failed on ${NODES[1]} -- if the proposal passed but late, cancel the plan (see gov_software_upgrade.sh --help)"

    if [[ -n "$encl_args" ]]; then
        step "2i. promote $NEW_UNIQUE to active BEFORE the height"
        # Promotion is by enclave quorum, and validateEnclaveIdentities runs on a trigger --
        # restarting one node on its OLD binaries is the existing trigger (same as the live roll).
        restart_node "${NODES[1]}"
        for i in {60..1}; do
            st=$(identity_status "$NEW_UNIQUE")
            [[ "$st" == "active" ]] && break
            sleep 6
        done
        st=$(identity_status "$NEW_UNIQUE")
        [[ "$st" == "active" ]] || die "$NEW_UNIQUE is '$st', not active -- the swap at H would start an enclave the chain refuses.  CANCEL THE PLAN (MsgCancelUpgrade) before the height."
        say "  $NEW_UNIQUE active"
    fi

    step "2j. wait for the swap height"
    say "  querying the scheduled plan"
    # WHITESPACE-TOLERANT ON PURPOSE.  `q upgrade plan -o json` PRETTY-PRINTS ("height": "486"),
    # unlike `qadenad status`, whose compact output every other extractor here was written against.
    # A compact-only pattern silently yields an empty height, which then reads as "no plan" -- the
    # opposite of the truth, one line after the proposal passed.
    plan_h=$(rsh "${NODES[1]}" '~/qadena/bin/qadenad q upgrade plan -o json 2>/dev/null' | grep -oE '"height"[[:space:]]*:[[:space:]]*"?[0-9]+' | grep -oE '[0-9]+' | head -1) || true
    if [[ -z "$plan_h" ]]; then
        # AN EMPTY PLAN QUERY IS AMBIGUOUS, and the two meanings are opposite.  x/upgrade DELETES
        # the plan once it is applied, so "no plan" is the normal state AFTER a successful swap --
        # which a short height or a slow submit can reach before this line runs.  Treating it as
        # failure would fail a run that had just succeeded.  Ask the other question instead.
        applied_h=$(rsh "${NODES[1]}" "~/qadena/bin/qadenad q upgrade applied $PLAN 2>/dev/null" | grep -oE 'height[^0-9]*[0-9]+' | grep -oE '[0-9]+' | head -1) || true
        [[ -n "$applied_h" ]] || die "no plan named $PLAN is scheduled and none has been applied -- the proposal passed, so either it carried a different name or the plan was cancelled"
        say "  plan $PLAN was ALREADY applied at height $applied_h"
        plan_h="$applied_h"
    else
        say "  plan height $plan_h"
        while :; do
            h=$(height_of "${NODES[1]}") || true
            # Nodes restart AT the height, so an unanswering RPC here is the swap happening.
            if [[ -z "$h" ]]; then say "  ... (RPC quiet -- restarting?)"; sleep 5; continue; fi
            (( h >= plan_h + 2 )) && break
            say "  ... $h / $plan_h"
            sleep 10
        done
    fi

    step "2k. verify every node swapped and is live"
    sleep 10
    for n in "${NODES[@]}"; do
        cur=$(rsh "$n" 'readlink ~/qadena/cosmovisor/current 2>/dev/null' | tr -d '
')
        [[ "$cur" == *"upgrades/$PLAN"* ]] || die "$n: current -> '$cur', expected upgrades/$PLAN -- cosmovisor did not swap (preupgrade hook failure?  see the node's log)"
        ver=$(rsh "$n" '~/qadena/bin/qadenad version 2>/dev/null' | tr -d '
' | head -1)
        [[ "$ver" == "$SRC_CHAIN" ]] || die "$n: runs $ver, expected $SRC_CHAIN"
        say "  $n: current -> $cur, version $ver"
    done
    for n in "${NODES[@]}"; do
        h0=$(height_of "$n"); sleep 12; h1=$(height_of "$n"); cu=$(catching_up_of "$n")
        [[ -n "$h1" && "$h1" -gt "${h0:-0}" && "$cu" == "false" ]] \
            || die "$n: not live after the swap (h $h0->$h1, catching_up=$cu)"
        say "  $n advancing ($h0 -> $h1, caught up)"
    done

    step "final: ROLL COMPLETE (via governance)"
    say "every node swapped to $PLAN at height $plan_h in the same block"
    exit 0
fi

if (( ! SKIP_GOV )); then
    # With --build-from these come from the package's manifest (stage 0c), so they are not
    # required on the command line -- but under --dry-run nothing was built, so they are unknown.
    if (( DRY )) && [[ -n "$BUILD_FROM" ]]; then
        NEW_UNIQUE="${NEW_UNIQUE:-(from the manifest of the package 0c would build)}"
        NEW_SIGNER="${NEW_SIGNER:-(likewise)}"
    fi
    [[ -n "$NEW_UNIQUE" && -n "$NEW_SIGNER" ]] \
        || die "--unique and --signer are required unless --skip-governance or --build-from"
    step "2. register $NEW_UNIQUE by governance, and get it promoted"
    say "submitting from ${NODES[1]} (it also votes)"
    run "${NODES[1]}" "cd ~/qv3 && ./testscripts/test_update_enclave_identity.sh $NEW_UNIQUE $NEW_SIGNER unvalidated" >/dev/null
    # NEWEST PROPOSAL, VIA REVERSE PAGING -- not a filtered list.  `q gov proposals` PAGINATES at
    # 100 and this chain already holds over a thousand, so listing and taking the last entry finds
    # the hundredth-oldest proposal, or nothing at all.  (The same default silently truncated a
    # list-public-key reading during the last rollout and made an owner-count report wrong.)
    # --page-reverse --page-limit 1 asks the chain for exactly the newest one, which is immune to
    # how many exist.  Note the id is a quoted STRING with a space after the colon in the
    # pretty-printed output, so parse the JSON rather than grepping for `"id":"N"`.
    # FIND *OUR* PROPOSAL BY ITS CONTENT, not by being the newest.  "Newest" is a RACE: the
    # regression suite submits governance proposals continuously -- ids 27..31 on 2026-08-24 were
    # all its ("add bankscan-... to the whitelist", "regression test: unchanged params ...") -- so
    # between our submit and this query another can land.  Voting on that one would miss ours
    # entirely AND cast unintended votes on somebody else's proposal, and the old status-only
    # check could not tell the difference: a regression proposal in its voting period passes it.
    #
    # So: among recent proposals, take the one that is BOTH in its voting period AND names the
    # measurement we are registering.  Page-reverse for the same reason as ever -- the default
    # page of 100 would find the hundredth-oldest on a chain that holds thousands.
    plist=$(rsh "${NODES[1]}" '~/qadena/bin/qadenad q gov proposals --page-reverse --page-limit 20 -o json 2>/dev/null') || true
    [[ -n "$plist" ]] || die "could not list proposals on ${NODES[1]}"
    PROP=$(print -r -- "$plist" | python3 -c '
import json, sys
u = sys.argv[1]
try:
    ps = json.load(sys.stdin)["proposals"]
except Exception:
    sys.exit(0)
for p in ps:
    if p.get("status") != "PROPOSAL_STATUS_VOTING_PERIOD":
        continue
    if u in json.dumps(p):
        print(p["id"])
        break
' "$NEW_UNIQUE") || true
    [[ -n "$PROP" ]] \
        || die "no proposal in its voting period names $NEW_UNIQUE -- did the submit fail?  (checked the newest 20)"
    say "  proposal $PROP -- verified in its voting period AND naming $NEW_UNIQUE"
    CHAIN=$(rsh "${NODES[1]}" '~/qadena/bin/qadenad status 2>/dev/null' | tr ',' '\n' | grep -oE '"network":"[^"]+"' | cut -d'"' -f4) || true
    # QUORUM: one validator is 25% against a 33.4% quorum.  Every node votes.
    for n in "${NODES[@]:1}"; do
        k=$(rsh "$n" '~/qadena/bin/qadenad keys list --keyring-backend test 2>/dev/null' | grep -oE 'pioneer[0-9]+' | head -1) || true
        [[ -n "$k" ]] || { say "  $n: no pioneer key, skipping vote"; continue }
        say "  voting yes from $k on $n"
        run "$n" "~/qadena/bin/qadenad tx gov vote $PROP yes --from $k --keyring-backend test --chain-id $CHAIN --gas auto --gas-adjustment 1.4 --gas-prices 100000000aqdn -y" >/dev/null
    done

    # WAIT FOR THE PROPOSAL TO PASS BEFORE RESTARTING ANYTHING.
    #
    # The restart exists to TRIGGER validateEnclaveIdentities, which promotes an UNVALIDATED
    # identity row to active -- and that row DOES NOT EXIST until the proposal passes.  Restart
    # first and the trigger is spent on nothing: the post-restart UpdateHeight finds no row to
    # promote, and the promotion then waits for the next natural keyUpdateFrequency tick, which is
    # precisely the hours-long delay the restart was meant to avoid.  The script would sit out its
    # entire --wait-secs and fail, after governance had already passed -- the expensive half to redo.
    #
    # It also makes the VOTES safe by construction.  A proposal cannot pass on votes that are still
    # sitting in a mempool, so once this returns every vote is on chain.  Restarting earlier can
    # drop the primary's OWN vote, which it cast at submit time, with nothing to show for it.
    #
    # Before this existed the script restarted immediately after voting and won the race by luck --
    # the voting period here is short enough that the proposal usually passed first.
    if (( ! DRY )); then
        say "waiting for proposal $PROP to pass (up to ${WAIT_SECS}s) before restarting anything"
        pwaited=0
        while true; do
            pst=$(rsh "${NODES[1]}" "~/qadena/bin/qadenad q gov proposal $PROP -o json 2>/dev/null" \
                  | grep -oE 'PROPOSAL_STATUS_[A-Z_]+' | head -1) || true
            if [[ "$pst" == "PROPOSAL_STATUS_PASSED" ]]; then
                say "  proposal $PROP PASSED after ${pwaited}s"
                break
            fi
            # A REJECTION WITH NO "NO" VOTES IS A QUORUM FAILURE, not a rejection on merit, and it
            # reads identically in the status.  Say so here rather than leaving it to be puzzled out.
            if [[ "$pst" == "PROPOSAL_STATUS_REJECTED" || "$pst" == "PROPOSAL_STATUS_FAILED" ]]; then
                die "proposal $PROP is $pst -- $NEW_UNIQUE will never be registered.  Check the tally before assuming it was voted down: a rejection showing ZERO no-votes is a failure to reach the 33.4% quorum, which needs at least two validators voting."
            fi
            sleep 10; pwaited=$(( pwaited + 10 ))
            (( pwaited % 60 == 0 )) && say "    ${pwaited}s  status=${pst:-(unreadable -- is ${NODES[1]} up?)}"
            (( pwaited < WAIT_SECS )) \
                || die "proposal $PROP is still ${pst:-unreadable} after ${WAIT_SECS}s -- not restarting anything on a proposal that has not passed"
        done
    fi

    say "restarting ${NODES[1]} on its OLD enclave to trigger the identity check"
    (( DRY )) || restart_node "${NODES[1]}"

    say "waiting for $NEW_UNIQUE to become active (up to ${WAIT_SECS}s)"
    if (( ! DRY )); then
        waited=0
        while [[ "$(identity_status $NEW_UNIQUE)" != "active" && $waited -lt $WAIT_SECS ]]; do
            sleep 15; waited=$(( waited + 15 ))
            st=$(identity_status $NEW_UNIQUE)
            # AN EMPTY STATUS IS AMBIGUOUS and that ambiguity wasted a full wait window once:
            # it means EITHER "the chain has not promoted it yet" OR "the node we are asking is
            # down".  Distinguish them, or a dead node looks exactly like a slow chain.
            if [[ -z "$st" ]]; then
                if [[ -z "$(height_of ${NODES[1]})" ]]; then
                    die "${NODES[1]} stopped answering while waiting for promotion -- it is DOWN, not slow"
                fi
                st="(not registered yet)"
            fi
            printf "    %4ds  status=%s\n" "$waited" "$st"
        done
        [[ "$(identity_status $NEW_UNIQUE)" == "active" ]] || die "$NEW_UNIQUE never became active"
        say "  ACTIVE"
    fi
fi

step "3. roll the fleet, one node at a time"
for n in "${NODES[@]}"; do
    say "$n: activating"
    # DO NOT HAND-ROLL THIS LOOP.  require_advancing below is the only thing standing between a
    # rolling upgrade and a halted chain: on four equal validators, taking a SECOND node down
    # before the first is back leaves 50%, which is under the two-thirds threshold, and the chain
    # stops with every process still running and no error anywhere.  That happened on 2026-08-23
    # doing exactly this by hand -- see backlog 108.
    # The signer keeps its name across a non-reproducible rebuild; move it aside (never delete --
    # the old enclave must stay on disk for the handover).
    run "$n" 'mkdir -p ~/qadena/bin/superseded; for f in ~/qadena/bin/signer_enclave.unique*; do [ -e "$f" ] && mv -f "$f" ~/qadena/bin/superseded/ ; done; true' >/dev/null 2>&1 || true
    # REDIRECT ON THE REMOTE SIDE, or this hangs forever.  install_release.sh --restart leaves the
    # node running DETACHED (PPID 1), and that process inherits THIS ssh session's stdout and
    # stderr.  ssh does not close the channel until every process holding those fds has exited --
    # and the one holding them is the node, which never exits.  So the install completes, the node
    # comes up healthy, and the roll sits forever on a pipe that will never close.
    #
    # On 2026-08-24 that hung the roll after M1: install_release.sh had already exited, M1 was up
    # and advancing on the new enclave, and the script waited 9 minutes on nothing before it was
    # noticed.  It would have waited indefinitely -- there is no timeout on this call.
    #
    # Sending the remote output to a file and fetching it afterwards is what lets the channel
    # close.  The build stage above carries the same note for the same reason; this is that trap
    # arriving through install_release.sh instead.
    ILOG="/tmp/install_release_$$.log"
    irc=0
    run "$n" "~/qadena/scripts/install_release.sh $REMOTE --wait-active=$WAIT_SECS --restart > $ILOG 2>&1 < /dev/null" || irc=$?
    if (( ! DRY )); then
        rsh "$n" "tail -40 $ILOG" 2>/dev/null | while read -r l; do say "    $l"; done
    fi
    (( irc == 0 )) || die "[$n] install_release.sh FAILED (exit $irc) -- full output in $n:$ILOG"
    (( DRY )) || sleep 20
    (( DRY )) || require_advancing "$n"
    say "  $n now on $(measure_of $n)"
done

step "4. final state"
for n in "${NODES[@]}"; do say "$n  enclave=$(measure_of $n)  height=$(height_of $n)"; done
print ""
say "Watch the next rotation tick for the audit:  grep 'ss-reshare: AUDIT' ~/qadena/logs/qadena.log"
