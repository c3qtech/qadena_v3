#!/bin/zsh
# Prepare a node's MACHINE: stop it, update its checkout, build, install, init genesis, package.
#
# The companion to nth_node_bringup.sh, which adds a node to a chain that already exists.  Nothing
# creates the FIRST node, and nothing refreshes a machine onto a newer commit -- both were done by
# hand every time, and the hand-run is where the traps below live.
#
# Run from a workstation with ssh access to the target.  Like nth_node_bringup.sh it drives the
# machine over ssh rather than living on it, so a run is reproducible from one place and the
# commands are visible in one transcript.
#
#   ./1st_node_bringup.sh --primary 192.168.86.120 --build-sgx
#
# Phases are separately runnable (--from/--until/--only): the build is ~24 minutes and there is no
# reason to repeat it to redo a start.
#
# ---------------------------------------------------------------------------------------------
# WHY THIS SCRIPT EXISTS
#
# Every trap below cost real time on 2026-08-15, doing exactly this by hand:
#
#   1. A STALE ROOT-OWNED LOG FILE SILENTLY EATS THE RUN.  `nohup sudo ... > /tmp/start120.log`
#      failed with "Permission denied" because a root-owned file of that name was left by an
#      earlier run.  The redirect failing means THE COMMAND NEVER RAN -- but `tail` of that same
#      path then printed the OLD run's contents, which read like a plausible current result.  Two
#      wrong conclusions came out of that before it was noticed.  Logs here go under the login
#      user's home with a run-specific name, and are removed first.
#
#   2. A HOST CAN HAVE MORE THAN ONE CHECKOUT.  .120 had ~/qv3 AND ~/test/qadena_v3 at different
#      commits.  The installed $QADENAHOME/scripts resolve their build directory from their OWN
#      location (setup_env.sh), so which one you invoke decides which tree you get.  This script
#      takes --repo explicitly and PRINTS the commit it actually built, because "I built the fix"
#      and "the node is running the fix" are different claims.
#
#   3. NEVER pgrep/pkill -f A PATTERN CONTAINING "qadenad" OVER SSH.  The remote shell running your
#      command matches it.  stop_qadena.sh reported "qadenad is STILL running after SIGKILL" when
#      the only match was the ssh command asking the question.  Match with a bracket class.
#
#   4. init.sh REFUSES TO RUN AS ROOT, but an SGX node MUST BE STARTED WITH sudo -- the enclave
#      opens /dev/sgx_enclave.  Two different privilege levels in adjacent phases.
#
#   5. UNDER sudo, ~ IS /root.  Resolve the checkout and home as the login user, then hand absolute
#      paths to the privileged command.
#
#   6. --build-sgx RUNS `git clean -fd` FIRST.  Uncommitted work in the target's checkout is
#      DESTROYED.  Phase 3 refuses a dirty tree rather than discovering this afterwards.
#
#   8. `zsh -lc` DOES NOT GET THE USER'S LOGIN PATH WHEN THE LOGIN SHELL IS bash.  On .120 go is
#      at /usr/local/go/bin/go, present under `bash -lc` and ABSENT under `zsh -lc` -- so a
#      toolchain check written the obvious way reports "go is not installed" on a machine that
#      builds fine by hand.  Toolchain probes here check known locations too, and build commands
#      prepend the path rather than trusting whichever rc file happens to run.
#
#   7. THE MEASUREMENT MUST MATCH GENESIS.  A joiner whose enclave differs by one byte is refused
#      by verifyRemoteReport, and the error names the measurement rather than the cause.  Phase 5
#      compares the built binary against what genesis recorded, while the two are still in reach.

set -u

PRIMARY=""
JOINER=""
REPO=""
REPO_DEFAULT="qv3"
REF=""
BUILD_SGX=0
ADVERTISE=""
PKG_OUT="/tmp/pkg"
FORCE=0
FROM=1
UNTIL=8
ONLY=""

fail() { print -u2 "FAIL(1st_node_bringup): $*"; exit 1 }
info() { print "  $*" }
phase() { print ""; print "======================================================================"; print ">>> $*"; print "======================================================================" }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --primary)   PRIMARY="$2"; shift 2 ;;
        --joiner)    JOINER="$2"; shift 2 ;;
        --repo)      REPO="$2"; shift 2 ;;
        --ref)       REF="$2"; shift 2 ;;
        --build-sgx) BUILD_SGX=1; shift ;;
        --advertise-ip-address) ADVERTISE="$2"; shift 2 ;;
        --package-out) PKG_OUT="$2"; shift 2 ;;
        --force)     FORCE=1; shift ;;
        --from)      FROM="$2"; shift 2 ;;
        --until)     UNTIL="$2"; shift 2 ;;
        --only)      ONLY="$2"; shift 2 ;;
        --help)
            print "Usage: 1st_node_bringup.sh --primary <ip> [--joiner <ip>] [--repo <path>] [--ref <git-ref>]"
            print "                          [--build-sgx] [--advertise-ip-address <ip>]"
            print "                          [--package-out <dir>] [--force]"
            print "                          [--from N] [--until N] [--only N]"
            print ""
            print "  --repo        checkout on the TARGET, relative to its home unless absolute."
            print "                Default \$HOME/$REPO_DEFAULT.  A host may have more than one"
            print "                checkout at different commits, so this is explicit on purpose."
            print "  --ref         git ref to build.  Default: leave the checkout where it is, and"
            print "                just report the commit.  Passing a ref does fetch + reset --hard"
            print "                + clean -fd, which DESTROYS uncommitted work on the target."
            print "  --build-sgx   reproducible docker build, ~24 min, real SGX measurements."
            print "                Without it you get a DEBUG enclave with go:embed'ed placeholder"
            print "                ids -- fine for logic, useless for attestation."
            print "  --advertise-ip-address   defaults to --primary."
            print "  --force       proceed even if the target's checkout is dirty (its changes will"
            print "                be destroyed by the build's git clean -fd)."
            print "  --joiner      a node to install the freshly built package onto (phase 8).  This"
            print "                is the seam with nth_node_bringup.sh, which assumes the joiner"
            print "                ALREADY has matching binaries -- its phase 1 checks the joiner's"
            print "                measurement against genesis and stops if it differs.  Installing"
            print "                from the primary's own package makes them match by construction."
            print ""
            print "  1 preflight   reachable; checkout present; toolchain present; SGX if asked for"
            print "  2 stop        stop node + enclaves, and PROVE nothing survived"
            print "  3 update      fetch/reset the checkout to --ref; report the commit built"
            print "  4 build+init  init.sh -- builds, WIPES \$QADENAHOME, re-inits genesis, installs"
            print "  5 verify      built measurement == the one genesis recorded"
            print "  6 start       start the node (sudo only where SGX) and wait for blocks"
            print "  7 package     package_release.sh, and print the joiner's install command"
            print "  8 distribute  install that package on --joiner, so nth_node_bringup.sh can start"
            exit 0 ;;
        *) fail "unknown option $1" ;;
    esac
done

[[ -n "$PRIMARY" ]] || fail "--primary is required"
[[ "$FROM"  == <-> ]] || fail "--from takes a phase number, got \"$FROM\""
[[ "$UNTIL" == <-> ]] || fail "--until takes a phase number, got \"$UNTIL\""
[[ "$FROM" -le "$UNTIL" ]] || fail "--from $FROM is after --until $UNTIL, so nothing would run"
# STRIP ANY user@ PREFIX.  --primary accepts user@host so a node can be driven as a specific
# account, but what init.sh wants here is a bare IP: it goes into config.toml's p2p address, and
# CometBFT parses that as <nodeid>@<host>:<port>.  Passing "user@host" produces two '@' and the node
# refuses to start with
#
#     address (5b7c44dc...@alvillarica-no-sgx-groups@192.168.86.140:26656) does not contain ID
#     run.sh: Process qadenad (real enclave) has exited with RC 1
#
# which reads as a p2p/identity problem rather than a mangled argument, and takes the signer and
# delayed_init_enclave down with it as collateral.
[[ -n "$ADVERTISE" ]] || ADVERTISE="${PRIMARY##*@}"

# rsh -- run as root through a LOGIN zsh, so PATH and setup_env.sh's definitions are present.
rsh() {
    local host="$1"; shift
    ssh -o ConnectTimeout=10 -o BatchMode=yes "$host" "sudo zsh -lc $(printf '%q' "$*")"
}
# rsh_user -- same, unprivileged, for anything that must not create root-owned files (trap 1).
rsh_user() {
    local host="$1"; shift
    ssh -o ConnectTimeout=10 -o BatchMode=yes "$host" "zsh -lc $(printf '%q' "$*")"
}

# BUILD_PATH -- prepended to any command that compiles or packages (trap 8).  Belt and braces: the
# login shell's PATH may or may not have go, and which rc file runs depends on the target's shell.
BUILD_PATH='export PATH=/usr/local/go/bin:$HOME/go/bin:$PATH;'

run_phase() {
    [[ -n "$ONLY" ]] && { [[ "$1" == "$ONLY" ]] && return 0 || return 1 }
    [[ "$1" -ge "$FROM" ]]  || return 1
    [[ "$1" -le "$UNTIL" ]] || return 1
    return 0
}

# SGX_PROBE -- run on a target, answers BOTH questions at once via its exit status.
#
#   0  both devices present AND openable by the login user   -> SGX, no root needed
#   1  both present but NOT openable                          -> SGX, root needed
#   2  not both present                                       -> no usable SGX (debug)
#
# -r/-w is access(2), which honours group membership; setup_qadena_build.sh puts the login user in
# the groups owning the devices, so 0 is the normal case on a provisioned machine.  /dev/isgx is not
# accepted -- see scripts/setup_env.sh for why.
SGX_PROBE='e=""; p=""
for d in /dev/sgx_enclave /dev/sgx/enclave;     do [ -e "$d" ] && { e="$d"; break; }; done
for d in /dev/sgx_provision /dev/sgx/provision; do [ -e "$d" ] && { p="$d"; break; }; done
[ -n "$e" ] && [ -n "$p" ] || exit 2
[ -r "$e" ] && [ -w "$e" ] && [ -r "$p" ] && [ -w "$p" ] || exit 1
exit 0'

sgx_state() { ssh -o ConnectTimeout=10 "$1" "$SGX_PROBE" >/dev/null 2>&1; print $? }

# sudo_for -- Q2 ONLY: "sudo " when this host's devices are out of reach, empty otherwise.
#
# ROOT IS AN SGX REQUIREMENT, NOT A QADENA ONE, and on a machine setup_qadena_build.sh has
# provisioned it is not even that: the login user is in the device groups and opens them directly.
# Asking "does a device EXIST" -- which this used to do -- returns sudo on exactly those machines,
# and using sudo needlessly is actively harmful: every file the node creates becomes root-owned, so
# the tree cannot be removed or reinstalled unprivileged, and the enclave's socket is left in sticky
# /tmp where only root can unlink it, breaking the next unprivileged start.
sudo_for() {
    [[ $(sgx_state "$1") == 1 ]] && print "sudo " || print ""
}

HOME_DIR=$(rsh_user "$PRIMARY" 'print $HOME' | tr -d '\r') || fail "cannot ssh to $PRIMARY"
[[ -n "$HOME_DIR" ]] || fail "could not resolve the login user's home on $PRIMARY"
case "$REPO" in
    "")  REPO="$HOME_DIR/$REPO_DEFAULT" ;;
    /*)  ;;
    *)   REPO="$HOME_DIR/$REPO" ;;
esac
NODE_HOME="$HOME_DIR/qadena"
RUNLOG="$HOME_DIR/primary_bringup.$$.log"   # trap 1: fresh name, user-owned, never /tmp

# REPORT THE STATE, DO NOT INFER IT FROM $SUDO.
#
# Under the old existence-based gate, empty SUDO meant exactly one thing -- no SGX device -- so the
# banner said so.  Now that the gate asks whether the devices are USABLE, empty means EITHER "SGX is
# present and we can open it" (the normal, provisioned case) OR "there is no SGX", and the old
# wording picks the wrong one.  On .120 it printed "no SGX device -- this will be a DEBUG enclave
# regardless of --build-sgx" while sitting on a working SGX box about to do a real SGX build: the
# reassuring half of the message was true and the informative half was exactly backwards.
SGX_STATE=$(sgx_state "$PRIMARY")
case "$SGX_STATE" in
    0) SUDO=""      ; SGX_DESC="present, devices usable by $(rsh_user "$PRIMARY" 'print $USER' | tr -d '\r') -- no sudo needed" ;;
    1) SUDO="sudo " ; SGX_DESC="present, but this user cannot open the devices -- commands will use sudo" ;;
    2) SUDO=""      ; SGX_DESC="NOT present (or only one of the two devices) -- debug enclave" ;;
    *) fail "could not probe SGX state on $PRIMARY (probe exited $SGX_STATE)" ;;
esac

info "target        $PRIMARY"
info "checkout      $REPO"
info "node home     $NODE_HOME"
info "sgx           $SGX_DESC"
info "privilege     ${SUDO:-none needed}"

# The warning belongs to SGX state 2 alone, never to "no sudo".  A provisioned machine reaches state
# 0 -- no sudo AND a perfectly real SGX build -- which the old condition flagged as debug.
if (( BUILD_SGX )) && [[ "$SGX_STATE" == 2 ]]; then
    info "NOTE: --build-sgx asked for, but the SGX devices are not both present -- this would be a"
    info "      DEBUG enclave wearing an SGX label, and it could not attest.  Phase 1 refuses it."
fi

# ---------------------------------------------------------------------------------------------
run_phase 1 && phase "1. preflight"
if run_phase 1; then
    rsh_user "$PRIMARY" "test -d $REPO/.git" \
        || fail "$REPO is not a git checkout on $PRIMARY (pass --repo)"

    # Name every checkout we can see. A second one at a different commit is not an error, but it
    # IS the thing that makes "which code is this node running?" ambiguous (trap 2).
    local_others=$(rsh_user "$PRIMARY" 'for d in $HOME/qv3 $HOME/qadena_v3 $HOME/test/qv3 $HOME/test/qadena_v3; do [[ -d $d/.git ]] && print "$d $(git -C $d rev-parse --short HEAD 2>/dev/null)"; done' | tr -d '\r')
    print "$local_others" | while read -r line; do [[ -n "$line" ]] && info "checkout: $line"; done
    if [[ $(print "$local_others" | grep -c .) -gt 1 ]]; then
        info "MORE THAN ONE CHECKOUT -- building $REPO; the others are ignored but may confuse"
        info "anyone reading \$QADENAHOME/scripts, which resolve their build dir from their own path"
    fi

    for t in go git; do
        rsh_user "$PRIMARY" "$BUILD_PATH command -v $t >/dev/null" \
            || fail "$t not found on $PRIMARY, even with /usr/local/go/bin and \$HOME/go/bin on PATH"
    done
    if (( BUILD_SGX )); then
        rsh_user "$PRIMARY" 'command -v ego >/dev/null' || fail "--build-sgx needs ego on $PRIMARY (run ubuntu/setup_qadena_build.sh)"
        rsh_user "$PRIMARY" 'command -v docker >/dev/null' || fail "--build-sgx is a docker build; docker is missing on $PRIMARY"
        # Q1: BOTH devices.  Provisioning is what attestation quotes with, so a box with only the
        # enclave node builds and runs fine and then fails at JOIN time with an error naming a
        # measurement rather than a missing device.
        [[ $(sgx_state "$PRIMARY") == 2 ]] \
            && fail "--build-sgx but the SGX devices are not both present on $PRIMARY: the result would be a debug enclave wearing an SGX label, and it could not attest"
    fi
    avail=$(rsh_user "$PRIMARY" "df --output=avail -BG $HOME_DIR | tail -1 | tr -dc '0-9'" | tr -d '\r')
    [[ -n "$avail" && "$avail" -ge 20 ]] || info "WARNING: only ${avail:-?}G free on $PRIMARY; a build plus a chain wants more"
    info "preflight ok"
fi

# ---------------------------------------------------------------------------------------------
run_phase 2 && phase "2. stop the node and prove it stopped"
if run_phase 2; then
    if rsh_user "$PRIMARY" "test -x $NODE_HOME/scripts/stop_qadena.sh"; then
        rsh "$PRIMARY" "$NODE_HOME/scripts/stop_qadena.sh --all" 2>&1 | tail -5 | while read -r l; do info "$l"; done
    else
        info "no $NODE_HOME/scripts/stop_qadena.sh (never installed?) -- nothing to stop"
    fi

    # trap 3: the bracket class is what stops this matching our own ssh command line.
    sleep 3
    left=$(ssh -o ConnectTimeout=10 "$PRIMARY" 'ps -eo pid,cmd | grep -E "qaden[a]d|eg[o] run|ego-hos[t]|signer_enclav[e]" | grep -v grep | wc -l' | tr -d '\r')
    [[ "$left" == "0" ]] || {
        ssh -o ConnectTimeout=10 "$PRIMARY" 'ps -eo pid,cmd | grep -E "qaden[a]d|eg[o] run|ego-hos[t]|signer_enclav[e]" | grep -v grep' | while read -r l; do info "$l"; done
        fail "$left process(es) survived the stop; kill them BY PID and re-run --only 2"
    }
    info "stopped: nothing matching the node or its enclaves is left"

    # CLEAR ROOT-OWNED LEFTOVERS, or an unprivileged start fails in a way that names neither the
    # file nor the reason.
    #
    # /tmp is sticky (1777), so the login user cannot unlink a socket left by a run that WAS root --
    # which is every run before the sudo gate was fixed.  The enclave then fails to bind with
    # "address already in use" and exits, taking the node down with it.  Same for a
    # root-owned log we might later redirect into: the redirect fails, the
    # command never runs, and a tail of that path serves the PREVIOUS run's output as if it were
    # current -- which cost two wrong conclusions on 2026-08-15.
    #
    # Done with sudo unconditionally: these files are root-owned precisely when it matters, and
    # removing a file we own needs no privilege anyway.
    rsh "$PRIMARY" 'rm -f /tmp/qadena_*.sock' 2>/dev/null || true
    left=$(ssh -o ConnectTimeout=10 "$PRIMARY" 'ls /tmp/qadena_*.sock 2>/dev/null | wc -l' | tr -d '\r')
    [[ "$left" == "0" ]] || fail "could not remove /tmp/qadena_*.sock on $PRIMARY; the enclave will not be able to bind"
    info "cleared stale enclave sockets"

    # $QADENAHOME may be full of root-owned files from earlier sudo runs.  init.sh removes it with
    # sudo when it has to, but say so here rather than letting phase 4 look like it hung.
    rootowned=$(rsh "$PRIMARY" "find $NODE_HOME -user root 2>/dev/null | head -1" | tr -d '\r')
    [[ -n "$rootowned" ]] && info "note: $NODE_HOME contains root-owned files; init.sh will need sudo to remove it"
fi

# ---------------------------------------------------------------------------------------------
run_phase 3 && phase "3. update the checkout"
if run_phase 3; then
    dirty=$(rsh_user "$PRIMARY" "git -C $REPO status --porcelain | head -20" | tr -d '\r')
    if [[ -n "$dirty" ]]; then
        print "$dirty" | while read -r l; do info "dirty: $l"; done
        # trap 6: the build's own git clean -fd would delete this without asking.
        (( FORCE )) || fail "$REPO has uncommitted work, which the build's 'git clean -fd' will DESTROY. Commit it, or pass --force."
        info "--force: proceeding, and the above WILL be destroyed"
    fi

    if [[ -n "$REF" ]]; then
        rsh_user "$PRIMARY" "git -C $REPO fetch --quiet --all --prune" || fail "git fetch failed on $PRIMARY"

        # RESOLVE THE REF ON THE TARGET, because a fetch creates REMOTE-TRACKING refs, not local
        # branches.  `--ref enclave-selfstart` names a branch that exists on origin and, on a
        # machine that has never checked it out, nowhere else -- so the reset died with
        #
        #     fatal: ambiguous argument 'enclave-selfstart': unknown revision or path not in the
        #     working tree
        #
        # which reads like the branch was never pushed.  It was; the target simply has it as
        # origin/enclave-selfstart.  Prefer an exact match (a tag, a sha, or a branch the target
        # really does have locally), then fall back to origin/<ref>, and SAY which was used --
        # "the ref I asked for" and "the commit it built" must stay distinguishable.
        # Plain, not `local`: this block runs at TOP LEVEL (phase 3 is an `if run_phase 3` block,
        # not a function), and zsh refuses `local` outside a function at RUNTIME -- which zsh -n
        # does not catch.
        resolved=""
        if rsh_user "$PRIMARY" "git -C $REPO rev-parse --verify --quiet '$REF^{commit}'" > /dev/null 2>&1; then
            resolved="$REF"
        elif rsh_user "$PRIMARY" "git -C $REPO rev-parse --verify --quiet 'origin/$REF^{commit}'" > /dev/null 2>&1; then
            resolved="origin/$REF"
            info "ref           $REF is not local on the target; using $resolved"
        else
            fail "neither '$REF' nor 'origin/$REF' exists on $PRIMARY after a fetch -- is it pushed?"
        fi

        rsh_user "$PRIMARY" "git -C $REPO reset --quiet --hard $resolved" || fail "git reset --hard $resolved failed on $PRIMARY"
        rsh_user "$PRIMARY" "git -C $REPO clean -qfd" || fail "git clean failed on $PRIMARY"
    else
        info "no --ref: leaving the checkout where it is"
    fi

    BUILT_COMMIT=$(rsh_user "$PRIMARY" "git -C $REPO rev-parse --short HEAD" | tr -d '\r')
    BUILT_SUBJ=$(rsh_user "$PRIMARY" "git -C $REPO log -1 --format=%s" | tr -d '\r')
    info "building commit $BUILT_COMMIT  ($BUILT_SUBJ)"
fi

# ---------------------------------------------------------------------------------------------
run_phase 4 && phase "4. build, wipe the home, re-init genesis, install"
if run_phase 4; then
    (( BUILD_SGX )) && info "reproducible docker build: expect ~24 minutes"
    info "NOTE: init.sh REMOVES $NODE_HOME entirely, including any chain history on this machine"

    sgx_flag=""
    (( BUILD_SGX )) && sgx_flag=" --build-sgx"

    # trap 4: init.sh refuses to run as root.  trap 1: a fresh, user-owned log.
    # The redirect matters for a second reason -- without it the ssh channel stays open for as long
    # as the build runs, which looks like a hang.
    rsh_user "$PRIMARY" "rm -f $RUNLOG"
    ssh -o ConnectTimeout=10 "$PRIMARY" \
        "cd $REPO && nohup zsh -lc '$BUILD_PATH ./buildscripts/init.sh --advertise-ip-address $ADVERTISE$sgx_flag' > $RUNLOG 2>&1 &" \
        || fail "could not launch init.sh on $PRIMARY"

    info "waiting for init.sh to finish (log: $PRIMARY:$RUNLOG)"
    while ssh -o ConnectTimeout=10 "$PRIMARY" 'pgrep -f "buildscripts/init\.s[h]" >/dev/null' 2>/dev/null; do
        sleep 30
    done

    if ! rsh_user "$PRIMARY" "grep -q 'FINAL BUILD SUCCESS' $RUNLOG"; then
        rsh_user "$PRIMARY" "tail -25 $RUNLOG" | while read -r l; do info "$l"; done
        fail "init.sh did not report success; see $PRIMARY:$RUNLOG"
    fi
    info "build + init reported success"
fi

# ---------------------------------------------------------------------------------------------
run_phase 5 && phase "5. the built measurement must be the one genesis recorded"
if run_phase 5; then
    # Compare while both are in reach.  Later this failure appears on the JOINER, as
    # verifyRemoteReport naming a measurement, with nothing to say it came from a rebuild here.
    gen=$(rsh_user "$PRIMARY" "jq -r '.app_state.qadena.enclaveIdentityList[0].uniqueID' $NODE_HOME/config/genesis.json" | tr -d '\r')
    # ASK THE BINARY, NOT THE FLAG -- same reasoning as phase 8 below.  Keying on (( BUILD_SGX ))
    # describes this invocation's command line, not the artefact: `--only 5` on an SGX box without
    # the flag would read the EMBEDDED id, which every enclave carries (test_unique_id.txt is
    # //go:embed-ed) and which does not describe an ego-signed one.  Here the flag is usually right
    # because phase 4 just built, but "usually right" is how the phase-8 version passed review.
    bin=$(rsh_user "$PRIMARY" "$BUILD_PATH cd $REPO && ego uniqueid cmd/qadenad_enclave/qadenad_enclave 2>/dev/null | head -1" | tr -d '\r')
    if [[ ! "$bin" =~ ^[0-9a-f]{64}$ ]]; then
        # A genuinely debug enclave, whose identity IS the embedded string.
        # EXTRACTED (-o), not line-matched.  Go packs string data without separators, so the
        # embedded id surfaces from `strings` mid-run ("... failed: unique047signer051 ...") and a
        # ^whole-line$ match can never hit it -- it matched a stray bare "unique" instead and
        # failed a build whose measurement was correct.  [0-9]+ so that bare "unique" cannot win.
        bin=$(rsh_user "$PRIMARY" "strings $REPO/cmd/qadenad_enclave/qadenad_enclave 2>/dev/null | grep -m1 -ohE 'unique[0-9]+'" | tr -d '\r')
    fi
    info "genesis records : ${gen:-<none>}"
    info "binary measures : ${bin:-<unreadable>}"
    [[ -n "$gen" && -n "$bin" ]] || fail "could not read one of them; refusing to call this verified"
    [[ "$gen" == "$bin" ]] || fail "measurement mismatch -- a joiner built from this tree will be refused by verifyRemoteReport"
    info "measurement matches genesis"
fi

# ---------------------------------------------------------------------------------------------
run_phase 6 && phase "6. start and confirm blocks"
if run_phase 6; then
    rsh_user "$PRIMARY" "rm -f $RUNLOG.start"
    # trap 4 again, mirrored: SGX must start WITH sudo, debug must not.
    ssh -o ConnectTimeout=10 "$PRIMARY" \
        "nohup ${SUDO}$NODE_HOME/scripts/start_qadena.sh > $RUNLOG.start 2>&1 &" \
        || fail "could not launch start_qadena.sh on $PRIMARY"

    info "waiting for the RPC to answer and the height to advance"
    h0=""; ok=0
    for i in {1..40}; do
        sleep 15
        h=$(ssh -o ConnectTimeout=10 "$PRIMARY" 'curl -s --max-time 5 localhost:26657/status 2>/dev/null | jq -r ".result.sync_info.latest_block_height // empty"' 2>/dev/null | tr -d '\r')
        [[ -z "$h" ]] && continue
        [[ -z "$h0" ]] && { h0="$h"; info "first height seen: $h0"; continue }
        if [[ "$h" -gt "$h0" ]]; then info "height advanced $h0 -> $h"; ok=1; break; fi
    done
    (( ok )) || {
        rsh_user "$PRIMARY" "tail -20 $RUNLOG.start" | while read -r l; do info "$l"; done
        fail "the node did not produce blocks; see $PRIMARY:$RUNLOG.start and $NODE_HOME/logs"
    }
fi

# ---------------------------------------------------------------------------------------------
run_phase 7 && phase "7. package for the joiners"
if run_phase 7; then
    # Build once, distribute: a joiner installed from THIS package has a measurement identical to
    # the primary's by construction.  Building the two independently is where drift bites.
    rsh_user "$PRIMARY" "rm -rf $PKG_OUT && mkdir -p $PKG_OUT"
    out=$(rsh_user "$PRIMARY" "$BUILD_PATH cd $REPO && ./buildscripts/package_release.sh --out $PKG_OUT 2>&1 | tail -25") \
        || { print "$out" | while read -r l; do info "$l"; done; fail "package_release.sh failed"; }
    print "$out" | while read -r l; do info "$l"; done

    tgz=$(rsh_user "$PRIMARY" "ls -1 $PKG_OUT/*.tar.gz 2>/dev/null | head -1" | tr -d '\r')
    [[ -n "$tgz" ]] || fail "package_release.sh produced no tarball in $PKG_OUT"
    info ""
    info "package: $PRIMARY:$tgz"
    # PREFER PHASE 8 over doing this by hand.  It stops the joiner first (install.sh replaces
    # binaries a running enclave holds open), decides sudo per host via sudo_for, and verifies the
    # result against the primary's genesis.  The by-hand form below is the fallback, and it does
    # NOT say sudo: installing writes only into the operator's own ~/qadena, and a sudo install
    # leaves that tree root-owned, after which their own CLI cannot read config/client.toml.  This
    # line used to print `sudo ./install.sh`, it was followed, and that is exactly what happened.
    info "to install on a joiner:"
    info "    $0 --primary $PRIMARY --joiner <joiner> --only 8"
    info "or by hand, as the user who will own the node (no sudo):"
    info "    scp $PRIMARY:$tgz /tmp/ && scp /tmp/$(basename $tgz) <joiner>:/tmp/"
    info "    ssh <joiner> 'cd /tmp && tar xzf $(basename $tgz) && ./${$(basename $tgz)%.tar.gz}/install.sh'"
    info "then:"
    info "    ./testscripts/nth_node_bringup.sh --primary $PRIMARY --joiner <joiner> \\"
    info "        --pioneer <a-name-the-chain-has-never-seen> --state-sync --from 1 --until 5"
fi

# ---------------------------------------------------------------------------------------------
run_phase 8 && phase "8. install the package on the joiner"
if run_phase 8 && [[ -n "$JOINER" ]]; then
    # THE SEAM WITH nth_node_bringup.sh.  Its phase 1 refuses to proceed unless the joiner's
    # measurement matches genesis, and it has no way to fix a mismatch -- that is this phase's job.
    # Installing the PRIMARY's own package is what makes them match by construction; building the
    # joiner independently from "the same" source is where drift bites.
    tgz=$(rsh_user "$PRIMARY" "ls -1 $PKG_OUT/*.tar.gz 2>/dev/null | head -1" | tr -d '\r')
    [[ -n "$tgz" ]] || fail "no package in $PRIMARY:$PKG_OUT -- run phase 7 first"
    base=$(basename "$tgz")
    dir="${base%.tar.gz}"

    JHOME=$(rsh_user "$JOINER" 'print $HOME' | tr -d '\r') || fail "cannot ssh to joiner $JOINER"
    SUDO_J=$(sudo_for "$JOINER")

    # Stop the joiner first: install.sh replaces binaries a running enclave has open.
    if rsh_user "$JOINER" "test -x $JHOME/qadena/scripts/stop_qadena.sh"; then
        rsh "$JOINER" "$JHOME/qadena/scripts/stop_qadena.sh --all" >/dev/null 2>&1 || true
        sleep 3
        left=$(ssh -o ConnectTimeout=10 "$JOINER" 'ps -eo pid,cmd | grep -E "qaden[a]d|eg[o] run|ego-hos[t]" | grep -v grep | wc -l' | tr -d '\r')
        [[ "$left" == "0" ]] || fail "joiner still has $left process(es) running; kill by PID and re-run --only 8"
    fi

    # Relay through the workstation rather than primary->joiner directly: we already have ssh to
    # both, and the two nodes need not be able to reach each other's accounts.
    info "copying $base to $JOINER"
    ssh -o ConnectTimeout=10 "$PRIMARY" "cat $tgz" | ssh -o ConnectTimeout=10 "$JOINER" "cat > /tmp/$base" \
        || fail "could not copy the package to $JOINER"

    info "installing on $JOINER"
    out=$(ssh -o ConnectTimeout=10 "$JOINER" "cd /tmp && rm -rf $dir && tar xzf $base && ${SUDO_J}./$dir/install.sh 2>&1 | tail -20") \
        || { print "$out" | while read -r l; do info "$l"; done; fail "install.sh failed on $JOINER"; }
    print "$out" | while read -r l; do info "$l"; done

    # Verify against the PRIMARY's genesis: the joiner has no genesis of its own until it joins.
    gen=$(rsh_user "$PRIMARY" "jq -r '.app_state.qadena.enclaveIdentityList[0].uniqueID' $NODE_HOME/config/genesis.json" | tr -d '\r')
    # ASK THE BINARY, NOT THE FLAG.  This used to branch on (( BUILD_SGX )) -- whether THIS
    # INVOCATION was told to build for SGX -- which is a statement about the command line, not
    # about the artefact sitting on the joiner.  Distributing a package built earlier
    # (--from 7, no --build-sgx) therefore took the debug branch and read the EMBEDDED id.
    #
    # That branch cannot fail, which is what makes it dangerous: cmd/qadenad_enclave/
    # test_unique_id.txt is //go:embed-ed (enclave.go:198), so the literal "unique047" is compiled
    # into EVERY enclave -- including a real ego-signed one, where it does not describe the binary
    # at all.  So a correctly installed SGX enclave measuring b43e245d... reported "unique047",
    # was compared against genesis, and the joiner was refused over a measurement it does not have.
    # (test_enclave_upgrade.sh's header says this outright: on SGX the *.txt files are still
    # embedded but the MEASUREMENT is the identity.)
    #
    # ego first, because only ego can compute a measurement; the embedded string is the fallback
    # for a genuinely debug enclave, where it IS the identity.
    jbin=$(rsh_user "$JOINER" "$BUILD_PATH ego uniqueid $JHOME/qadena/bin/qadenad_enclave 2>/dev/null | head -1" | tr -d '\r')
    if [[ ! "$jbin" =~ ^[0-9a-f]{64}$ ]]; then
        # Not ego-signed (or no ego here): a debug enclave, whose identity really is the embedded
        # string.  Extracted with -o because Go packs string data -- the id never sits on its own
        # line, so a ^whole-line$ match can only ever find a stray bare "unique".
        jbin=$(rsh_user "$JOINER" "strings $JHOME/qadena/bin/qadenad_enclave 2>/dev/null | grep -m1 -ohE 'unique[0-9]+'" | tr -d '\r')
    fi
    # COMPARE AGAINST THE SEED'S CURRENT ENCLAVE, NOT GENESIS.  Genesis names the measurement the
    # chain LAUNCHED with, forever; after an enclave upgrade every node runs something else.  This
    # check used to assert joiner == genesis, which is the one value that CANNOT join an upgraded
    # chain: nth_node_bringup phase 1 requires the joiner to run the SEED's measurement, because a
    # joiner bootstraps its trusted set from a seed running its own build.  So on an upgraded chain
    # this phase reported "verified" for a node phase 1 then refused -- which is exactly what
    # happened here (genesis unique047, primary unique048, joiner installed at unique047).
    #
    # Genesis is still printed, as context for the upgrade, but it is not the assertion.
    pbin=$(rsh_user "$PRIMARY" "$BUILD_PATH ego uniqueid $NODE_HOME/bin/qadenad_enclave 2>/dev/null | head -1" | tr -d '\r')
    if [[ ! "$pbin" =~ ^[0-9a-f]{64}$ ]]; then
        pbin=$(rsh_user "$PRIMARY" "strings $NODE_HOME/bin/qadenad_enclave 2>/dev/null | grep -m1 -ohE 'unique[0-9]+'" | tr -d '\r')
    fi
    info "primary genesis records : ${gen:-<none>}"
    info "primary enclave measures: ${pbin:-<unreadable>}"
    info "joiner binary measures  : ${jbin:-<unreadable>}"
    [[ -n "$pbin" && -n "$jbin" ]] || fail "could not read one of them; refusing to call this verified"
    [[ "$pbin" == "$jbin" ]] || fail "joiner measurement != the primary's enclave ($pbin) --
nth_node_bringup.sh phase 1 would refuse it.  If install.sh reported the new enclave as STAGED
rather than installed, the joiner is still running its previous build."
    if [[ -n "$gen" && "$gen" != "$pbin" ]]; then
        info "joiner matches the primary's enclave (genesis names $gen -- normal after an upgrade)"
    else
        info "joiner measurement matches the primary's enclave"
    fi

    info ""
    info "READY FOR nth_node_bringup.sh.  Next:"
    info "    ./testscripts/nth_node_bringup.sh --primary $PRIMARY --joiner $JOINER \\"
    info "        --pioneer <a-name-the-chain-has-never-seen> --state-sync --from 1 --until 5"
    info "  (state-sync needs the chain past height 1500, and a snapshot to have been taken --"
    info "   lower snapshot-interval in $NODE_HOME/config/app.toml if you are not waiting for 2000)"
elif run_phase 8; then
    info "no --joiner given; nothing to distribute to"
fi

print ""
print "1st_node_bringup: done (phases ${ONLY:-$FROM..$UNTIL})"
