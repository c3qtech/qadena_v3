#!/bin/zsh
# The whole fleet bringup, unattended, from one directory: build and start the primary, run the
# full regression, package what the regression LEFT RUNNING, install and join every joiner.
#
#   ./full_fleet_bringup.sh --primary alvillarica@192.168.86.120 \
#                           --joiner  alvillarica@192.168.86.140
#
#   ./full_fleet_bringup.sh --primary m1 --joiner m2 --joiner m3 --joiner m4
#
# EVERY LOG LANDS IN ONE DIRECTORY ON THIS MACHINE (--run-dir, default
# ~/qadena-fleet-runs/<timestamp>, with a `latest` symlink).  Remote logs are pulled in as the run
# proceeds, so tailing that one directory shows the whole fleet without an ssh session per node.
#
# --joiner is REPEATABLE, and joiners are brought up one at a time, in order.  Serial is not
# laziness: each join re-splits stake, and two of those racing is a consensus problem rather than a
# test.  Each gets its own pioneer name (pioneer2, pioneer3, ...), because add_full_node.sh refuses
# a name the chain has already seen.
#
# YOU DO NOT HAVE TO KNOW WHETHER THE TARGETS ARE SGX.  The same command line works either way:
# every host is probed and the build kind follows from what is actually there -- a reproducible
# signed build with real measurements on SGX hardware, a debug enclave on anything else (including
# every ARM box, where ego ships as an amd64-only .deb and does not exist at all).  Nothing
# downstream needs telling either: 1st_node_bringup and nth_node_bringup already decide privilege
# per host and already read the measurement from the binary rather than from a flag.
#
# ---------------------------------------------------------------------------------------------
# THE ORDER IS THE POINT, and getting it wrong is what this script exists to prevent.
#
#   1. PACKAGE AFTER THE ENCLAVE UPGRADE, NEVER BEFORE.  regression.sh --with-enclave-upgrade
#      registers a NEW enclave identity and leaves the primary running it.  A package built before
#      that measures the old one, and nth_node_bringup's phase 1 then refuses the joiner --
#      correctly, because a joiner bootstraps its trusted set from a seed running its OWN build, so
#      it must match the seed's CURRENT measurement, not the one genesis recorded.  This cost a
#      full SGX sequence on 2026-08-18: build, install, regression, all fine, and the join refused
#      at the last step with a measurement mismatch that read as a build fault and was an ordering
#      fault.  Stages run: start -> regress -> package -> install -> join.
#
#   2. AND DO NOT REBUILD AFTER THE UPGRADE EITHER.  test_enclave_upgrade.sh bumps the //go:embed-ed
#      id files, builds, and RESTORES them on exit, so the checkout no longer describes the running
#      node: a later build_enclave.sh on that machine silently produces the PRE-upgrade identity.
#      Packaging is safe -- package_release.sh takes the INSTALLED artifacts -- which is exactly why
#      stage D packages rather than rebuilds.
#
#   3. NEVER RUN A SUITE WHILE THE CONTINUOUS LOOP IS RUNNING.  They share ann, pioneer1 and the
#      treasury, and the collisions surface as "could not provision" or "Invalid destination
#      EWalletID" -- which read as chain bugs and are not.  Stage C refuses to start until the loop
#      is stopped BY PID and the in-flight run has drained.
#
#   4. ANYTHING THAT BUILDS NEEDS A LOGIN SHELL AND AN EXPLICIT PATH.  A non-login ssh command has
#      no /usr/local/go/bin, and --with-enclave-upgrade then reports "could not build the enclave at
#      <id>" while the real error is "command not found: go" -- and it leaves the node STOPPED.
#      Remote launches here go through `bash -lc` with the build path prepended.
#
#   5. ssh + nohup + & LEAKS THE CHANNEL: the session stays open even with output redirected, so the
#      local call never returns and reads as a hang.  Long-runners use ssh -f.
#
#   6. A JOINER WITH AN OLD INSTALL FAILS TO INSTALL CLEANLY.  install.sh refuses to overwrite a
#      versioned binary whose contents differ.  Each joiner's ~/qadena is archived (moved aside,
#      never deleted) before anything installs.
#
#   7. PROCESSES BEING UP IS NOT HEALTH.  On a two-validator fleet a single divergent node halts the
#      chain -- neither side has 2/3 -- with every process still running.  Between stages this
#      checks that the height is ADVANCING, not merely that something answers.
#
#   8. pgrep PATTERNS ARE BRACKET-CLASSED so the ssh command carrying them never matches itself.
#
# Traps 1-4 and 7 were reported by the peer session driving the same fleet on 2026-08-18/19; the
# ordering fix in particular is theirs.
#
# THE ONE HARD STOP: a failed regression halts the run. Nothing is packaged, installed or joined off
# a red suite.  --skip-regression exists for a fast re-bringup and is exactly the flag to leave off.

set -u

SCRIPT_DIR="${0:A:h}"
# Captured before the parser consumes them, so the run directory records what was actually asked
# for.  Reconstructing it afterwards from the variables loses every default that was not overridden.
INVOCATION="$0 $*"

PRIMARY=""
JOINERS=()
REF="main"
BUILD_SGX="auto"           # auto | yes | no
PIONEER_PREFIX="pioneer"
SKIP="enclave-rollback,enclave-crash,enclave-upgrade"
SNAP_INTERVAL=2000
SNAP_WAIT_MIN=120
REGRESSION_WAIT_MIN=300
SKIP_REGRESSION=0
RUN_DIR=""
NO_LOOP=0
BLOCK_SYNC=0
# --from <stage>.  The sub-scripts have been phase-addressable all along; the fleet script was not,
# so a failure at stage C meant redoing a ~24-minute SGX build that had already succeeded and whose
# artifacts were still installed and healthy.  See TESTING-BACKLOG.md item 89.
FROM_STAGE="A0"
# Set in stage D, but read in E and in the summary -- so a resume that skips D must still be able
# to answer "what is the primary running?".  Resolved lazily from the binary rather than carried.
PRIM_UID=""
STAGE_ORDER=(A0 A B C D E F G H)

# Helpers, and the traps they encode, live in ONE place -- fleet_bringup_with_tests.sh drives the
# same machines the same way and must not carry a second copy that can drift.  See fleet_lib.sh.
FLEET_NAME="${0:t:r}"
source "$SCRIPT_DIR/fleet_lib.sh"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --primary)       PRIMARY="$2"; shift 2 ;;
        --joiner)        JOINERS+=("$2"); shift 2 ;;
        --ref)           REF="$2"; shift 2 ;;
        --build-sgx)     BUILD_SGX="yes"; shift ;;
        --no-build-sgx)  BUILD_SGX="no"; shift ;;
        --pioneer-prefix) PIONEER_PREFIX="$2"; shift 2 ;;
        --snapshot-interval) SNAP_INTERVAL="$2"; shift 2 ;;
        --skip-regression) SKIP_REGRESSION=1; shift ;;
        --no-loop)       NO_LOOP=1; shift ;;
        --block-sync)    BLOCK_SYNC=1; shift ;;
        --from)          FROM_STAGE="${2:u}"; shift 2 ;;
        --run-dir)       RUN_DIR="$2"; shift 2 ;;
        --help)
            print "Usage: full_fleet_bringup.sh --primary <[user@]host> [--joiner <[user@]host>]..."
            print "                             [--run-dir <dir>] [--ref <git-ref>]"
            print "                             [--build-sgx | --no-build-sgx] [--pioneer-prefix <n>]"
            print "                             [--snapshot-interval N] [--skip-regression] [--no-loop]"
            print "                             [--block-sync] [--from <stage>]"
            print ""
            print "  --joiner            REPEATABLE.  Joiners are installed and joined serially."
            print "                      With none given, the primary is built and tested alone."
            print "  --run-dir           where every log for this run is collected on THIS machine."
            print "                      Default ~/qadena-fleet-runs/<timestamp>, plus a 'latest'"
            print "                      symlink.  Remote logs are pulled in as the run proceeds."
            print "  --build-sgx         force a reproducible SGX build (refused without devices)."
            print "  --no-build-sgx      force a DEBUG enclave even on SGX hardware -- skips the"
            print "                      ~24-minute docker build when only logic is being tested."
            print "                      NEITHER IS NORMALLY NEEDED: hosts are probed, and the same"
            print "                      command line works on an SGX fleet and an ARM/debug one."
            print "  --skip-regression   skip stage C.  It is the stage that proves the chain works"
            print "                      before anything joins it, so leaving it off is the default."
            print "  --no-loop           do not start continuous regression after the suite."
            print "  --from <stage>      resume at a stage (A0 A B C D E F G H) instead of the top."
            print "                      For recovering from a late failure without repeating work"
            print "                      that already succeeded -- an SGX build is ~24 minutes, and"
            print "                      a flake at stage C should not cost it.  --from D or later"
            print "                      SKIPS THE REGRESSION and says so; stepping over that guard"
            print "                      should be a deliberate act, never a quiet one."
            print "  --block-sync        join by BLOCK-SYNC, skipping the wait for state-sync to"
            print "                      become eligible (~50 min for 2000 blocks at 1.5s).  Use it"
            print "                      when the point is to HAVE a second node quickly.  It is NOT"
            print "                      the same test: state-sync seeds the joiner's enclave store"
            print "                      from a snapshot, and a block-synced joiner never exercises"
            print "                      that path -- so the default stays state-sync."
            print ""
            print "  A0 preflight EVERY host -- nothing is stopped or moved until all of them pass"
            print "  A  archive each joiner's old ~/qadena (moved aside, never deleted)"
            print "  B  1st_node_bringup phases 1-6: build, init, start the primary"
            print "  C  full regression --with-enclave-upgrade; MUST pass; loop must be stopped"
            print "  D  1st_node_bringup phase 7: package what the upgrade LEFT RUNNING"
            print "  E  1st_node_bringup phase 8 per joiner: install that package"
            print "  F  continuous regression on the primary (chain-restarting suites skipped)"
            print "  G  wait for height past the snapshot interval and a snapshot on disk"
            print "  H  nth_node_bringup --state-sync for each joiner in turn"
            exit 0 ;;
        *) print -u2 "unknown option $1"; exit 1 ;;
    esac
done

[[ -n "$PRIMARY" ]] || { print -u2 "FAIL: --primary is required"; exit 1 }

# ---------------------------------------------------------------------------------------------
# ONE DIRECTORY FOR THE WHOLE RUN.  Everything this script prints, everything the sub-scripts print,
# and a periodically-refreshed copy of each remote log, so the run can be watched from here without
# an ssh session per node.
STAMP=$(date +%Y%m%d-%H%M%S)
[[ -n "$RUN_DIR" ]] || RUN_DIR="$HOME/qadena-fleet-runs/$STAMP"
mkdir -p "$RUN_DIR" || { print -u2 "FAIL: could not create $RUN_DIR"; exit 1 }
ln -sfn "$RUN_DIR" "${RUN_DIR:h}/latest" 2>/dev/null

STATUS="$RUN_DIR/status.txt"

# Everything from here on is teed into the run directory as well as the terminal.
exec > >(tee -a "$RUN_DIR/run.log") 2>&1

note "run started: $INVOCATION"


# run_stage <letter> -- true once we have reached --from.  Stages are letters rather than numbers
# because they are named that way everywhere else (logs, --help, the run directory).
FROM_INDEX=$(stage_index "$FROM_STAGE") \
    || { print -u2 "FAIL: --from takes one of ${STAGE_ORDER[*]}, got \"$FROM_STAGE\""; exit 1 }

# RESUMING PAST A RED REGRESSION IS A DELIBERATE ACT.  --from D or later skips stage C entirely, so
# say so out loud: the guard that refuses to package off a failed suite is the point of this script,
# and stepping over it should never be quiet.
if [[ $FROM_INDEX -gt $(stage_index C) ]]; then
    print "  NOTE: --from $FROM_STAGE skips the regression (stage C).  Nothing will re-verify this"
    print "        chain before packaging and joining -- make sure you know why the last run stopped."
fi

# Trap 4: builds go through a LOGIN bash with the toolchain path prepended.  zsh -lc is not enough
# when the target's login shell is bash -- go is then absent and the failure names the enclave.

# Pull a remote log into the run directory.  Cheap, and it is what makes one-directory monitoring
# real rather than a claim -- the local copy is never more than a poll interval behind.

# Trap 7: the height must ADVANCE.  Processes being up says nothing -- a halted two-validator chain
# looks perfectly healthy from ps.

# Same probe 1st_node_bringup uses: 0 = SGX usable, 1 = SGX present, needs root, 2 = no SGX.

# READ THE MEASUREMENT FROM THE BINARY, TWO WAYS.  ego computes it on SGX; on ARM (no ego at all)
# and on debug builds the identity IS the embedded string.  Never `qadenad_enclave --unique-id` on
# SGX: it returns the embedded debug placeholder, which does not describe a signed enclave.

rsh_user "$PRIMARY" 'print $HOME' >/dev/null 2>&1 || fail "cannot ssh to $PRIMARY"
for j in "${JOINERS[@]}"; do
    rsh_user "$j" 'print $HOME' >/dev/null 2>&1 || fail "cannot ssh to joiner $j"
done
PHOME=$(rsh_user "$PRIMARY" 'print $HOME' | tr -d '\r')
REG_LOG="$PHOME/regression_full.$STAMP.log"
LOOP_LOG="$PHOME/regression_continuous.$STAMP.log"

# DECIDE THE BUILD KIND ON EVIDENCE.  The operator does not have to know what this hardware is.
PSTATE=$(sgx_state "$PRIMARY")
[[ "$PSTATE" == <-> ]] || fail "could not probe SGX state on $PRIMARY"
# ego is what build.sh actually keys on -- see the auto branch below.
PRIMARY_HAS_EGO=0
rsh_user "$PRIMARY" 'command -v ego >/dev/null 2>&1' && PRIMARY_HAS_EGO=1
case "$BUILD_SGX" in
    # THE BUILD KEYS ON ego, THE RUNTIME KEYS ON THE DEVICES, and they are not the same question.
    # This used to decide purely on devices, which is wrong in one direction that matters: a box with
    # ego but no /dev/sgx_* was called "debug" here while build.sh went on to build SGX anyway,
    # because ego is a BUILD dependency and needs no device.  Report what will actually be built.
    auto) if (( PRIMARY_HAS_EGO )); then
              if [[ "$PSTATE" == 2 ]]; then
                  # Can build SGX, cannot run it.  Do not pass --build-sgx (phase 1 would refuse on
                  # the missing devices) and do not claim debug either -- build.sh's default still
                  # produces a signed enclave this host cannot load.
                  SGX_FLAG=""; KIND="SGX (ego present, but NO devices -- see the warning below)"
              else
                  SGX_FLAG="--build-sgx"; KIND="SGX (ego and devices present)"
              fi
          else
              SGX_FLAG=""; KIND="debug (no ego on the primary, so build.sh cannot build SGX)"
          fi ;;
    yes)  SGX_FLAG="--build-sgx"; KIND="SGX (forced)"
          [[ "$PSTATE" == 2 ]] && fail "--build-sgx but $PRIMARY has no SGX devices: that would be a debug enclave wearing an SGX label, and it could not attest"
          (( PRIMARY_HAS_EGO )) || fail "--build-sgx but $PRIMARY has no ego, which is what signs the enclave. Provision it (ubuntu/setup_qadena_build.sh) or drop the flag." ;;
    # MUST PASS --no-sgx, not merely omit --build-sgx.  Omitting it left build.sh to its default,
    # which is "ego installed means SGX" -- so on an Intel box this printed "debug (forced)" in the
    # run log and produced a SIGNED SGX BUILD.  A flag that reported the opposite of what it did,
    # in a script written to catch exactly that.  It only appeared to work on ARM, where there is no
    # ego for the default to key on.  See TESTING-BACKLOG.md item 90.
    no)   SGX_FLAG="--no-sgx"; KIND="debug (forced with --no-sgx)" ;;
esac

# The one combination that cannot work: an ego-signed enclave needs /dev/sgx_enclave to RUN, so an
# SGX build cannot be installed onto a joiner without the devices.  The reverse is fine.  Refused
# here, before a ~24-minute build, rather than at that joiner's first start.
if [[ -n "$SGX_FLAG" ]]; then
    for j in "${JOINERS[@]}"; do
        [[ $(sgx_state "$j") == 2 ]] \
            && fail "$j has no SGX devices but the primary builds an SGX enclave -- that binary cannot run there. Drop that joiner, provision its devices, or pass --no-build-sgx for a debug fleet."
    done
fi

# THE PACKAGE IS ARCHITECTURE-LOCKED, AND NOTHING IN IT SAYS SO.  It ships BOTH libwasmvm variants
# -- aarch64 and x86_64 -- which makes it look portable, but there is exactly one qadenad and one
# qadenad_enclave and they are the builder's architecture.  Neither the manifest nor install.sh
# checks, so a cross-arch install "succeeds" and fails later, naming a loader error rather than the
# mismatch.  An ARM rehearsal therefore validates the SEQUENCE and produces nothing reusable on an
# x86 fleet: that fleet must build its own package.
PARCH=$(rsh_user "$PRIMARY" 'uname -m' | tr -d '\r')
[[ -n "$PARCH" ]] || fail "could not read the primary's architecture"
for j in "${JOINERS[@]}"; do
    jarch=$(rsh_user "$j" 'uname -m' | tr -d '\r')
    [[ "$jarch" == "$PARCH" ]] \
        || fail "$j is $jarch but the primary is $PARCH. The package carries only the builder's binaries, so it cannot be installed there -- run a separate bringup with a $jarch primary for that group."
done
info "architecture  $PARCH (primary and all joiners agree)"

# The one configuration that builds something it cannot run.  Not fatal -- a build host is a real
# use for it -- but it must not be discovered when the node fails to start.
if (( PRIMARY_HAS_EGO )) && [[ "$PSTATE" == 2 && "$BUILD_SGX" == "auto" ]]; then
    info ""
    info "WARNING: $PRIMARY has ego but NO /dev/sgx_* devices."
    info "  build.sh defaults to SGX whenever ego is present, so this will produce a SIGNED enclave"
    info "  that this host cannot load -- the node will fail at startup, not at build time."
    info "  Pass --no-sgx for a debug fleet, or provision the SGX devices."
    info ""
fi

{
    print "run       $STAMP"
    print "primary   $PRIMARY"
    print "joiners   ${JOINERS[*]:-<none>}"
    print "ref       $REF"
    print "build     $KIND"
} > "$RUN_DIR/fleet.txt"

info "run dir       $RUN_DIR"
info "primary       $PRIMARY"
info "joiners       ${JOINERS[*]:-<none>}"
info "ref           $REF"
info "build         $KIND"
info "pioneers      ${PIONEER_PREFIX}2 .. ${PIONEER_PREFIX}$(( ${#JOINERS[@]} + 1 ))"

# ---------------------------------------------------------------------------------------------
if run_stage A0; then
stage "A0. preflight every host BEFORE anything is stopped or moved"
# NOTHING DESTRUCTIVE UNTIL EVERY CHEAP CHECK HAS PASSED ON EVERY HOST.  This stage used to be the
# archive below, which meant a joiner's ~/qadena was moved aside and THEN the primary turned out to
# be unbuildable -- on the first run of this script that cost a 1.2G tree moved for a run that died
# at stage B seconds later.  Delegating to 1st_node_bringup's own phase 1 keeps one definition of
# "can this machine do the job": toolchain presence AND version, checkout cleanliness, disk, SGX.
# See TESTING-BACKLOG.md item 85.
"$SCRIPT_DIR/1st_node_bringup.sh" --primary "$PRIMARY" --ref "$REF" $SGX_FLAG --only 1 \
    2>&1 | tee "$RUN_DIR/stage-A0-preflight.log"
[[ ${pipestatus[1]} -eq 0 ]] || fail "the primary failed preflight; nothing has been changed on any host. See $RUN_DIR/stage-A0-preflight.log"

# The joiners do not build, so they need less -- but they DO need to be reachable, stoppable and
# have room for the install, and finding that out after the primary's 24-minute build is a waste.
for j in "${JOINERS[@]}"; do
    javail=$(rsh_user "$j" 'df --output=avail -BG $HOME | tail -1 | tr -dc "0-9"' | tr -d '\r')
    [[ -n "$javail" && "$javail" -ge 10 ]] \
        || info "WARNING: only ${javail:-?}G free on $j; an install plus a chain wants more"
done
info "all hosts preflighted"

# ---------------------------------------------------------------------------------------------
fi

if run_stage A; then
stage "A. archive each joiner's previous install"
# Trap 6.  Moved aside, never deleted: the old keyring and chain data stay recoverable.
for j in "${JOINERS[@]}"; do
    jhome=$(rsh_user "$j" 'print $HOME' | tr -d '\r')
    if rsh_user "$j" "test -d $jhome/qadena"; then
        if rsh_user "$j" "test -x $jhome/qadena/scripts/stop_qadena.sh"; then
            ssh -o ConnectTimeout=10 -o BatchMode=yes "$j" \
                "sudo zsh -lc $(printf '%q' "$jhome/qadena/scripts/stop_qadena.sh --all")" >/dev/null 2>&1 || true
            sleep 3
        fi
        left=$(ssh -o ConnectTimeout=10 "$j" 'ps -eo pid,cmd | grep -E "qaden[a]d|cosmoviso[r] run|eg[o] run|ego-hos[t]|signer_enclav[e]" | grep -v grep | wc -l' | tr -d '\r')
        [[ "$left" == "0" ]] || fail "$j still has $left node/enclave process(es); kill them BY PID and re-run"
        rsh_user "$j" "mv $jhome/qadena $jhome/qadena.pre-bringup.$STAMP.bak" \
            || fail "could not archive $j's old ~/qadena"
        info "$j: archived to $jhome/qadena.pre-bringup.$STAMP.bak"
    else
        info "$j: no ~/qadena to archive"
    fi
done

# ---------------------------------------------------------------------------------------------
fi

if run_stage B; then
stage "B. 1st_node_bringup phases 1-6: build, init and start the primary"
# Stops at 6 deliberately.  Packaging is stage D, AFTER the regression has upgraded the enclave --
# see trap 1.  This is the fix for the sequence that failed on 2026-08-18.
"$SCRIPT_DIR/1st_node_bringup.sh" --primary "$PRIMARY" --ref "$REF" $SGX_FLAG --from 1 --until 6 \
    2>&1 | tee "$RUN_DIR/stage-B-bringup.log"
[[ ${pipestatus[1]} -eq 0 ]] || fail "1st_node_bringup phases 1-6 failed; it is phase-resumable (--from N) once fixed. See $RUN_DIR/stage-B-bringup.log"
assert_advancing "$PRIMARY" "after bringup"

# ---------------------------------------------------------------------------------------------
fi

if run_stage C; then
stage "C. full regression --with-enclave-upgrade on the primary"
if (( SKIP_REGRESSION )); then
    info "--skip-regression: SKIPPED.  Nothing has proved this chain works, and the enclave has NOT"
    info "been upgraded, so the package in stage D will measure the build from stage B."
else
    # Trap 3: a suite must never share the chain with the loop.
    n=$(rsh_user "$PRIMARY" 'pgrep -f "run_regression_continuall[y]" | wc -l' | tr -d '[:space:]')
    if [[ "$n" != "0" ]]; then
        info "a continuous loop is running on the primary; stopping it by PID and draining the in-flight run"
        rsh_user "$PRIMARY" 'pkill -f "run_regression_continuall[y]"' >/dev/null 2>&1 || true
        i=0
        while (( i < 60 )); do
            r=$(rsh_user "$PRIMARY" 'pgrep -f "regression\.s[h]" | wc -l' | tr -d '[:space:]')
            [[ "$r" == "0" ]] && break
            sleep 30; (( i++ ))
        done
        (( i < 60 )) || fail "an in-flight regression run would not drain; stop it by PID and re-run"
        info "loop stopped and the chain is idle"
    fi

    # Trap 4: login bash + build path, or the enclave upgrade fails claiming a build error.
    rsh_build_detached "$PRIMARY" "$REG_LOG" "./testscripts/regression.sh --with-enclave-upgrade" \
        || fail "could not launch regression.sh on $PRIMARY"
    info "running; remote log $REG_LOG, mirrored to $RUN_DIR/stage-C-regression.log"

    i=0
    while (( i < REGRESSION_WAIT_MIN )); do
        sleep 60; (( i++ ))
        sync_log "$PRIMARY" "$REG_LOG" "stage-C-regression.log"
        n=$(rsh_user "$PRIMARY" 'pgrep -f "regression\.s[h]" | wc -l' 2>/dev/null | tr -d '[:space:]')
        [[ "$n" == "0" ]] && break
    done
    sync_log "$PRIMARY" "$REG_LOG" "stage-C-regression.log"
    (( i < REGRESSION_WAIT_MIN )) || fail "regression still running after $REGRESSION_WAIT_MIN minutes; see $RUN_DIR/stage-C-regression.log"

    grep -q 'SUITES PASSED' "$RUN_DIR/stage-C-regression.log" || {
        tail -40 "$RUN_DIR/stage-C-regression.log" | while read -r l; do info "$l"; done
        fail "the full regression did not pass -- nothing will be packaged, installed or joined off a red run. See $RUN_DIR/stage-C-regression.log"
    }
    grep 'SUITES PASSED' "$RUN_DIR/stage-C-regression.log" | while read -r l; do info "$l"; done
    info "full regression passed (~${i} min)"
    assert_advancing "$PRIMARY" "after regression"
fi

# ---------------------------------------------------------------------------------------------
fi

if run_stage D; then
stage "D. package what is actually running on the primary"
# Trap 1 and 2: this packages the INSTALLED artifacts, which after the upgrade are the new enclave.
# It does not rebuild -- a rebuild here would silently produce the PRE-upgrade identity, because the
# upgrade suite restores the embedded id files on exit.
"$SCRIPT_DIR/1st_node_bringup.sh" --primary "$PRIMARY" --only 7 \
    2>&1 | tee "$RUN_DIR/stage-D-package.log"
[[ ${pipestatus[1]} -eq 0 ]] || fail "packaging failed; see $RUN_DIR/stage-D-package.log"

PRIM_UID=$(measurement_of "$PRIMARY")
[[ -n "$PRIM_UID" ]] || fail "could not read the primary's enclave measurement"
info "primary now runs: $PRIM_UID"
print "primary measurement: $PRIM_UID" >> "$RUN_DIR/fleet.txt"

# ---------------------------------------------------------------------------------------------
fi

if run_stage E; then
stage "E. install that package on each joiner"
# RESUMING INTO THIS STAGE: stage D would normally have set PRIM_UID.  Read it from the binary now
# if we skipped D, so --from E verifies against what the primary is ACTUALLY running rather than
# failing on an unset variable -- or, worse, comparing against nothing.
if [[ -z "$PRIM_UID" ]]; then
    PRIM_UID=$(measurement_of "$PRIMARY")
    [[ -n "$PRIM_UID" ]] || fail "could not read the primary's enclave measurement"
    info "primary runs: $PRIM_UID (read now, since stage D was skipped)"
fi
for j in "${JOINERS[@]}"; do
    info ""
    info "installing on $j"
    "$SCRIPT_DIR/1st_node_bringup.sh" --primary "$PRIMARY" --joiner "$j" --only 8 \
        2>&1 | tee "$RUN_DIR/stage-E-install-${j##*@}.log"
    [[ ${pipestatus[1]} -eq 0 ]] || fail "install failed on $j; see $RUN_DIR/stage-E-install-${j##*@}.log"

    # VERIFY THE BINARY, not the installer's report.  install.sh has historically staged an enclave
    # and not switched to it on a node with no chain to ask about the identity, reporting success
    # while the old measurement stayed in place.
    juid=$(measurement_of "$j")
    [[ "$juid" == "$PRIM_UID" ]] \
        || fail "$j measures $juid but the primary runs $PRIM_UID -- nth_node_bringup phase 1 would refuse it. The package may predate an enclave upgrade."
    info "$j measures $juid -- matches the primary"
    print "$j measurement: $juid" >> "$RUN_DIR/fleet.txt"
done

# ---------------------------------------------------------------------------------------------
fi

if run_stage F; then
stage "F. continuous regression on the primary (skipping: $SKIP)"
# Trap 3 again, from the other side: with those three suites skipped the chain never restarts under
# a joining node, which is what makes nth_node_bringup's --quiesce unnecessary rather than merely
# omitted.  They stop and restart the node by design, and a state-syncing joiner dies when its
# primary's RPC vanishes.
if (( NO_LOOP )); then
    info "--no-loop: not starting continuous regression"
else
    rsh_build_detached "$PRIMARY" "$LOOP_LOG" "./testscripts/run_regression_continually.sh --skip $SKIP" \
        || fail "could not launch run_regression_continually.sh on $PRIMARY"
    sleep 10
    n=$(rsh_user "$PRIMARY" 'pgrep -f "run_regression_continuall[y]" | wc -l' | tr -d '[:space:]')
    [[ "$n" != "0" ]] || fail "the continuous loop did not start; see $LOOP_LOG on the primary"
    sync_log "$PRIMARY" "$LOOP_LOG" "stage-F-continuous.log"
    info "continuous loop running; mirrored to $RUN_DIR/stage-F-continuous.log"
fi

fi

if (( ${#JOINERS[@]} == 0 )); then
    print ""
    print "full_fleet_bringup: done (primary only).  Logs: $RUN_DIR"
    note "done: primary only"
    exit 0
fi

# ---------------------------------------------------------------------------------------------
if run_stage G; then
if (( BLOCK_SYNC )); then
    stage "G. (skipped -- --block-sync needs no snapshot)"
    # Block-sync replays from genesis, so it has no precondition beyond a chain producing blocks.
    # That is the whole saving: no ~50-minute wait for the snapshot interval.  It is a DIFFERENT
    # test, not a faster one -- see the note in stage H.
    assert_advancing "$PRIMARY" "before joining"
else
stage "G. wait for height past $SNAP_INTERVAL and a snapshot on disk"
# state-sync has nothing to sync FROM until the primary has taken a snapshot, and the joiner's
# failure in that case names a trust height rather than a missing snapshot.
i=0; h=""; s=""
while (( i < SNAP_WAIT_MIN )); do
    out=$(rsh_user "$PRIMARY" 'h=$(curl -s --max-time 5 localhost:26657/status | jq -r ".result.sync_info.latest_block_height // empty"); s=$(find $HOME/qadena/data/snapshots -maxdepth 1 -type d -regex ".*/[0-9]+" 2>/dev/null | wc -l); echo "$h $s"' 2>/dev/null | tr -d '\r')
    h=${out%% *}; s=${out##* }
    [[ -n "$h" && "$h" -gt $(( SNAP_INTERVAL + 5 )) && "$s" -ge 1 ]] && { info "ready: height=$h snapshots=$s"; break }
    (( i % 5 == 0 )) && info "height ${h:-?}, snapshots ${s:-0} -- waiting"
    sleep 60; (( i++ ))
    (( NO_LOOP )) || sync_log "$PRIMARY" "$LOOP_LOG" "stage-F-continuous.log"
done
(( i < SNAP_WAIT_MIN )) || fail "no snapshot after $SNAP_WAIT_MIN minutes (height=${h:-?} snapshots=${s:-?})"
fi
fi

# ---------------------------------------------------------------------------------------------
if run_stage H; then
stage "H. join each node by state-sync, in turn"
n=1
JOINED=()
for j in "${JOINERS[@]}"; do
    (( n++ ))
    pioneer="${PIONEER_PREFIX}${n}"
    # From the second joiner on, corroborate the state-sync trust height against a node that is NOT
    # the primary.  nth_node_bringup's --seed2 defaults to the primary, which proves only that the
    # primary agrees with itself; an independent peer is what makes the cross-check mean anything.
    seed2_arg=()
    if (( ${#JOINED[@]} > 0 )); then
        seed2_arg=(--seed2 "${JOINED[1]##*@}")
        info "cross-checking the trust height against ${JOINED[1]}"
    fi
    info ""
    # WHICH SYNC RAN IS RECORDED, because "the joiner caught up" means something different in each
    # case: a state-synced joiner IMPORTED the enclave-private tables from a snapshot, a block-synced
    # one replayed history and never touched that path.
    sync_arg=(--state-sync)
    sync_kind="state-sync"
    if (( BLOCK_SYNC )); then
        sync_arg=()
        sync_kind="block-sync"
    fi
    info "joining $j as $pioneer by $sync_kind"
    print "$j joined by: $sync_kind (as $pioneer)" >> "$RUN_DIR/fleet.txt"
    "$SCRIPT_DIR/nth_node_bringup.sh" --primary "$PRIMARY" --joiner "$j" \
        --pioneer "$pioneer" "${sync_arg[@]}" "${seed2_arg[@]}" --from 1 --until 5 \
        2>&1 | tee "$RUN_DIR/stage-H-join-${j##*@}.log"
    [[ ${pipestatus[1]} -eq 0 ]] || fail "join failed for $j; nth_node_bringup is phase-resumable (--from N). See $RUN_DIR/stage-H-join-${j##*@}.log"
    JOINED+=("$j")
    assert_advancing "$j" "after join"
    assert_advancing "$PRIMARY" "primary after $j joined"
    info "$j joined as $pioneer"
    note "joined $j as $pioneer"
done

fi

(( NO_LOOP )) || sync_log "$PRIMARY" "$LOOP_LOG" "stage-F-continuous.log"

print ""
print "full_fleet_bringup: done.  Primary + ${#JOINED[@]} joiner(s) up."
print "  logs           : $RUN_DIR   (also ${RUN_DIR:h}/latest)"
print "  build          : $KIND"
print "  measurement    : ${PRIM_UID:-unknown}  (identical on every node)"
print "  joined         : ${JOINED[*]}"
print "  archives       : ~/qadena.pre-bringup.$STAMP.bak on each joiner (delete once satisfied)"
print ""
print "Not done here, deliberately: converting joiners to validators (nth_node_bringup phases 6-7)."
print "That re-splits stake, and on a small fleet a single divergent node then halts the chain, so"
print "it is worth watching rather than automating:"
print "  ./testscripts/nth_node_bringup.sh --primary $PRIMARY --joiner <joiner> --from 6 --until 7"
note "done: ${#JOINED[@]} joiner(s)"
