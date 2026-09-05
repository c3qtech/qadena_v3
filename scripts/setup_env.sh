#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

# SGX RUNS ONLY UNDER LINUX (in practice Ubuntu, which is what the ego toolchain targets), so this
# probe is Linux-only by construction: /proc/cpuinfo does not exist on macOS and the grep simply
# fails there, leaving REAL_ENCLAVE=0.  That is correct, not a fallback.
#
# This detects the CPU and NOTHING ELSE.  It does not know how the enclave binary was built --
# buildscripts/build_enclave.sh gates the ego build on --build-sgx and never reads this
# variable.  Runtime scripts must therefore branch on use_real_enclave <binary> (below), never on
# REAL_ENCLAVE alone.
if grep sgx /proc/cpuinfo > /dev/null 2> /dev/null ; then
    # echo to stderr
    echo "SGX detected" >&2
    export REAL_ENCLAVE=1
else
    # echo to stderr
    echo "SGX not detected" >&2
    export REAL_ENCLAVE=0
fi

if [[ "$DOCKER_BUILD" = "1" ]]; then
    # echo to stderr
    echo "Docker build" >&2
else
    # echo to stderr
    echo "Host" >&2
fi

# check SCRIPT_DIR/../cmd and SCRIPT_DIR/../x  -- if they exist, then we are in a build environment
if [[ -d "$SCRIPT_DIR/../cmd" && -d "$SCRIPT_DIR/../x" ]]; then
    # if SUDO_USER
    if [[ -n "$SUDO_USER" ]]; then
        export QADENAHOME="$(getent passwd "$SUDO_USER" | cut -d: -f6)/qadena"
    else
        export QADENAHOME="$(cd ~ && pwd)/qadena"
    fi
    export qadenabuild="$(cd "$SCRIPT_DIR/.." && pwd)"
    export qadenabuildscripts="$qadenabuild/buildscripts"
    export qadenascripts="$qadenabuild/scripts"
    export qadenatestscripts="$qadenabuild/testscripts"
    export qadenatestdata="$qadenabuild/test_data"
    export qadenaproviderscripts="$qadenabuild/provider_scripts"
    export veritasscripts="$qadenabuild/veritas_scripts"
    export qadenafoundationscripts="$qadenabuild/foundation_scripts"

    echo "Qadena build: $qadenabuild" >&2
    echo "Qadena build scripts: $qadenabuildscripts" >&2
else
    # resolve $SCRIPT_DIR/.. to absolute path
    export QADENAHOME="$(cd "$SCRIPT_DIR/.." && pwd)"
    export qadenascripts="$QADENAHOME/scripts"
#    export qadenatestscripts="$QADENAHOME/testscripts"
    export qadenaproviderscripts="$QADENAHOME/provider_scripts"
    export veritasscripts="$QADENAHOME/veritas_scripts"
    # BOTH BRANCHES, ALWAYS.  qadenabuild is exported only above, so `$qadenabuild/foundation_scripts/x`
    # expands to `/foundation_scripts/x` here and the call fails on an installed node.  Every other
    # path in this file is set in both branches; this one has to be too.
    export qadenafoundationscripts="$QADENAHOME/foundation_scripts"
fi

export qadenabin="$QADENAHOME/bin"
# A FUNCTION, NOT AN ALIAS, SO IT CAN BRANCH ON THE SUBCOMMAND.
#
# --keyring-backend is NOT a global flag: `query` rejects it outright ("unknown flag"), so a
# wrapper that appends it unconditionally breaks every read -- and breaks them QUIETLY, because
# call sites pipe stderr to /dev/null and read an empty result as a legitimate answer.
#
# DEFAULT STAYS `test`, DELIBERATELY.  36 files under testscripts/ depend on it, and an unattended
# fleet run cannot type a passphrase.  A REAL deployment -- SEC's steps on their own machine, with
# keys that matter -- should export QADENA_KEYRING_BACKEND=file, which is the whole point of this
# being a variable.  The foundation_scripts/ already default to `file` on their own.
: ${QADENA_KEYRING_BACKEND:=test}
# THE SAME BINARY WITHOUT THE PASSPHRASE WRAPPER, for the handful of calls that must control
# their own stdin -- `keys add --recover`, which needs the mnemonic first and the passphrase after.
# WHERE THE KEYS LIVE, SEPARATELY FROM WHERE THE NODE LIVES.
#
# --home carries the node's config and data; --keyring-dir carries the keyring, and cosmos lets
# them differ.  That is what allows a caller to keep its OWN keys beside its own files -- SEC's
# steps put theirs in $VERITAS_SEC_HOME/keyring -- while still reading config from the node home.
# Unset, the keyring stays inside --home, which is what every other script in this tree expects.
_kr_dir_flag() { [ -n "${QADENA_KEYRING_DIR:-}" ] && print -- "--keyring-dir $QADENA_KEYRING_DIR" }

qadenad_alias_raw() {
    "$qadenabin/qadenad" --home "$QADENAHOME" --keyring-backend "$QADENA_KEYRING_BACKEND" \
        ${=$(_kr_dir_flag)} "$@"
}

qadenad_alias() {
    case "${1:-}" in
        keys|tx)
            # THE PASSPHRASE ONLY.  NO `cat`, DELIBERATELY.
            #
            # An earlier version forwarded the caller's stdin here so that
            # `echo "$mn" | qadenad_alias keys add x --recover` could work under backend=file.
            # It HANGS: when stdin is an open-but-empty pipe -- which is the normal state inside a
            # script -- `cat` waits for an EOF that never comes.  Measured 2026-09-05, a two-minute
            # block with no output.
            #
            # So this wrapper feeds the passphrase and nothing else, and a call that needs to pipe
            # something as well does its own redirection at the call site, where the ordering is
            # visible.  For the record, `keys add --recover` reads the MNEMONIC FIRST and the
            # passphrase after; putting the passphrase first makes qadenad report "invalid
            # mnemonic", blaming the wrong input.
            if [[ -n "${QADENA_KEYRING_PASS:-}" ]]; then
                { print -r -- "$QADENA_KEYRING_PASS"; print -r -- "$QADENA_KEYRING_PASS" } \
                  | "$qadenabin/qadenad" --home "$QADENAHOME" \
                        --keyring-backend "$QADENA_KEYRING_BACKEND" ${=$(_kr_dir_flag)} "$@"
            else
                "$qadenabin/qadenad" --home "$QADENAHOME" \
                    --keyring-backend "$QADENA_KEYRING_BACKEND" ${=$(_kr_dir_flag)} "$@"
            fi ;;
        *)  "$qadenabin/qadenad" --home "$QADENAHOME" "$@" ;;
    esac
}

# ASK ONCE PER RUN, NOT ONCE PER KEY.  A step creates several keys and reads several more; the
# file backend prompts on every one of them, and the prompt is invisible wherever a call site
# captures output.  Collected here and handed to each qadenad invocation by the wrapper above.
qadena_keyring_unlock() {
    [ "$QADENA_KEYRING_BACKEND" = "file" ] || return 0
    [ -z "${QADENA_KEYRING_PASS:-}" ] || return 0
    if [ -n "${QADENA_KEYRING_PASSFILE:-}" ]; then
        QADENA_KEYRING_PASS=$(head -1 "$QADENA_KEYRING_PASSFILE")
    else
        printf "Keyring passphrase for %s (hidden, will not echo): " "$QADENAHOME" >&2
        read -rs QADENA_KEYRING_PASS; echo "" >&2
        if [ ! -d "$QADENAHOME/keyring-file" ]; then
            printf "  confirm: " >&2; read -rs _kp2; echo "" >&2
            [ "$QADENA_KEYRING_PASS" = "$_kp2" ] || { echo "passphrases do not match" >&2; exit 1; }
            unset _kp2
        fi
    fi
    [ -n "$QADENA_KEYRING_PASS" ] || { echo "empty passphrase" >&2; exit 1; }
    export QADENA_KEYRING_PASS
}
export qadenad_binary="$qadenabin/qadenad"

export LD_LIBRARY_PATH="$qadenabin:$LD_LIBRARY_PATH"

# Is a systemd unit in charge of this node?
#
# WHY EVERY START/STOP MUST ASK.  The unit's ExecStart is run.sh, and Restart=on-failure exists to
# recover an enclave crash -- so a script that kills the processes directly RACES systemd: it
# restarts the unit seconds later, and the script's own start then launches a SECOND node beside
# it.  Two instances, one home, one port set, one enclave socket.  When the unit is present the
# scripts drive systemd instead of the processes.
#
# The FILE, not `is-active`: a stopped-but-installed unit still owns this node, and a stop that
# went around systemd would leave it free to restart the node behind us.
qadena_systemd_managed() {
    [ -f /etc/systemd/system/qadena.service ]
}


# ---------------------------------------------------------------------------------------------
# COSMOVISOR IS THE ONLY LAYOUT.  Every qadena node keeps its binaries in a generation directory
# under $QADENAHOME/cosmovisor and reaches them through symlinks in $QADENAHOME/bin.  There is no
# unmanaged mode: a node is born managed (init.sh / install_release.sh build the tree) and stays
# that way.
#
# WHY NO FALLBACK.  An auto-detecting run.sh looked tolerant but was worse: `rm -rf $QADENAHOME`
# (init.sh, reset_qadena_fast.sh) silently returned a node to a flat layout, where in-place binary
# installs are legal again -- which is precisely how unreplayable history gets reintroduced, and
# it did so QUIETLY.  Requiring the tree turns that into a loud failure with a fix-it command.
#
# The `current` symlink is the test, because it is the one thing cosmovisor itself maintains: a
# half-created cosmovisor/ directory does not count as a tree.
cosmovisor_managed() {
    [ -L "$QADENAHOME/cosmovisor/current" ]
}

# Where binaries actually live: the CURRENT generation's bin.  Every installer resolves its
# destination through this one function, so "where does a binary go" cannot drift between callers.
cosmovisor_gen_bin() {
    print -r -- "$QADENAHOME/cosmovisor/current/bin"
}

# Re-create $qadenabin's symlinks for whatever the current generation now holds.  Called after
# ANYTHING changes that directory's contents -- the libwasmvm .so files, in particular, only
# appear once binaries are installed, so init has to relink twice.
#
# RELATIVE targets: an archived home (qadena.pre-bringup.*.bak) then carries links that resolve
# inside the archive instead of dangling back at the live tree.
cosmovisor_relink() {
    local gen f b
    gen="$QADENAHOME/cosmovisor/current/bin"
    [ -d "$gen" ] || return 1
    mkdir -p "$qadenabin" || return 1
    for f in "$gen"/*(N); do
        b=${f:t}
        # Only ever replace a symlink or a missing name.  A REAL file here is either cosmovisor
        # itself or a versioned copy, and clobbering one would destroy the artifact the enclave
        # handover and the identity checks read.
        if [ -e "$qadenabin/$b" ] && [ ! -L "$qadenabin/$b" ]; then
            continue
        fi
        rm -f "$qadenabin/$b"
        ln -s "../cosmovisor/current/bin/$b" "$qadenabin/$b" || return 1
    done
    return 0
}

# The hard assertion that replaced the old silent fallback.  Anything that needs to run against a
# node's binaries calls this first.
cosmovisor_require() {
    local who="${1:-this command}"
    if ! cosmovisor_managed ; then
        echo "$who: $QADENAHOME is not a cosmovisor node (no cosmovisor/current)." >&2
        echo "        Every qadena node keeps its binaries in a generation directory; there is no" >&2
        echo "        flat layout any more.  Build one with buildscripts/init.sh, install a release" >&2
        echo "        package, or migrate an existing flat home with:" >&2
        echo "            scripts/cosmovisor_setup.sh --migrate" >&2
        return 1
    fi
    if [ ! -x "$qadenabin/cosmovisor" ] ; then
        echo "$who: no cosmovisor binary at $qadenabin/cosmovisor -- the tree exists but nothing can" >&2
        echo "        launch it.  buildscripts/build_cosmovisor.sh (build host), or reinstall a" >&2
        echo "        release package that carries it." >&2
        return 1
    fi
    return 0
}

# echo to stderr
echo "Qadena home: $QADENAHOME" >&2
echo "Qadena bin: $qadenabin" >&2
echo "Qadena scripts: $qadenascripts" >&2

# is_sgx_binary <path> -- true only for an ego-SIGNED SGX executable.
#
# `ego uniqueid` reads the enclave measurement out of the binary's Open Enclave section, so it
# succeeds on a signed binary and fails on one produced by a plain `go build`.  That is precisely the
# question being asked, and it needs no new tooling: run.sh already calls `ego uniqueid` on this very
# path to build the --enclave-unique-id flag.
is_sgx_binary() {
  local bin="$1"
  [[ -n "$bin" && -x "$bin" ]] || return 1
  command -v ego > /dev/null 2>&1 || return 1
  ego uniqueid "$bin" > /dev/null 2>&1
}

# use_real_enclave <path> -- the condition every runtime script should branch on.
#
# BOTH halves are required, and that is the whole point of this helper.
#
# REAL_ENCLAVE says only that the CPU reports SGX support (setup_env.sh greps /proc/cpuinfo).  It
# says NOTHING about how <path> was built -- buildscripts/build_enclave.sh gates the ego-go/ego sign
# build on --build-sgx and never consults REAL_ENCLAVE at all.  So on SGX hardware carrying
# a debug-built binary, branching on REAL_ENCLAVE alone sends a plain Go executable down the
# `ego run` path: the launch fails, `ego uniqueid` yields nothing, and run.sh interpolates an empty
# --enclave-unique-id.  Nothing in that failure names either cause.
#
# Ordered so the cheap CPU test short-circuits first: on a non-SGX host `ego` is never invoked, which
# matters because it usually is not installed there.
use_real_enclave() {
  [[ $REAL_ENCLAVE -eq 1 ]] || return 1
  is_sgx_binary "$1"
}

# warn_if_sgx_binary_missing <name> <path> -- say so, once, when the hardware and the binary disagree.
#
# Falling back to the debug path silently would be its own trap: an operator who asked for a real
# enclave would get a simulated one and no indication of it.
warn_if_sgx_binary_missing() {
  local name="$1" bin="$2"
  if [[ $REAL_ENCLAVE -eq 1 ]] && ! is_sgx_binary "$bin"; then
      echo "$name:  WARNING: SGX hardware detected, but $bin is not an ego-signed enclave." >&2
      echo "$name:           Running in DEBUG (simulated) mode.  To build a real enclave:" >&2
      echo "$name:           buildscripts/build.sh --build-sgx" >&2
  fi
}

# TWO SEPARATE QUESTIONS, and conflating them is what produced the sudo-everywhere habit:
#
#   Q1  Is there SGX here?              -> do we run under `ego` at all, or simulate?
#   Q2  Can THIS USER open the devices? -> do we need root?
#
# Q1 is answered by REAL_ENCLAVE + is_sgx_binary (see use_real_enclave above) and by sgx_present
# below.  Q2 is answered by sgx_usable_by_me, and is the ONLY question the root decision may
# consult.  Keeping them apart matters: an earlier single tri-state predicate let "no devices found"
# satisfy the ROOT check, so a machine with no SGX but an ego-signed binary got neither a root check
# nor a clear statement that it was about to simulate -- two different conditions sharing one answer.

# sgx_enclave_dev / sgx_provision_dev -- the in-kernel driver's two device nodes, or empty.
#
# /dev/sgx/{enclave,provision} are the compatibility symlinks the driver package creates; -e and
# -r/-w follow them, so either spelling works.
#
# /dev/isgx is deliberately NOT accepted.  That is the out-of-tree pre-5.11 driver's single node,
# which has no separate provisioning device.  ubuntu/setup_qadena_build.sh provisions only the two
# modern devices, and ego targets the in-kernel driver, so treating an isgx box as SGX-ready would
# promise attestation it structurally cannot deliver.
sgx_enclave_dev() {
  local d
  for d in /dev/sgx_enclave /dev/sgx/enclave; do [[ -e $d ]] && { print "$d"; return 0 } ; done
  return 1
}
sgx_provision_dev() {
  local d
  for d in /dev/sgx_provision /dev/sgx/provision; do [[ -e $d ]] && { print "$d"; return 0 } ; done
  return 1
}

# sgx_present -- Q1.  BOTH devices must exist.
#
# Both, not either: /dev/sgx_enclave runs the enclave, /dev/sgx_provision holds the provisioning key
# that ATTESTATION needs.  getRemoteReport/verifyRemoteReport gate sync-enclave, secret shares and
# the private-state transfer, so a box with only the first will run an enclave and then fail at JOIN
# time with an error naming a measurement rather than a missing device.
sgx_present() {
  sgx_enclave_dev > /dev/null && sgx_provision_dev > /dev/null
}

# sgx_usable_by_me -- Q2.  Both devices exist AND this user can open them.
#
# The test is -r/-w, i.e. access(2), which honours GROUP MEMBERSHIP -- exactly what `id -u` cannot
# see.  ubuntu/setup_qadena_build.sh adds the login user to the groups owning the devices (`sgx` for
# the enclave node and the DIFFERENT group `sgx_prv` for provisioning), so on a provisioned machine
# this is true and root is not needed at all.  Measured on .120:
#
#     crw-rw---- 1 root sgx     /dev/sgx_enclave
#     crw-rw---- 1 root sgx_prv /dev/sgx_provision
#     uid=1000(alvillarica) groups=...,108(sgx),...,1001(sgx_prv)
#
# access(2) is preferred over comparing `id -nG` with `stat -c %G` because it also covers what plain
# membership would miss: a device relaxed to 666, an ACL, or the caller already being root.  Where
# the two disagree, this one is right -- it answers "will the open succeed" rather than "does a rule
# imply it should".
sgx_usable_by_me() {
  local encl prov
  encl=$(sgx_enclave_dev)   || return 1
  prov=$(sgx_provision_dev) || return 1
  [[ -r $encl && -w $encl && -r $prov && -w $prov ]]
}

# needs_root_if_real_enclave <name> [binary]
#
# ROOT IS NOT A QADENA REQUIREMENT.  `ego run` needs to OPEN the SGX devices; whether that takes root
# depends on their group and this user's membership of it, which setup_qadena_build.sh already
# arranges.  This used to demand uid 0 whenever the enclave was real -- wrong on every machine that
# script had provisioned, and expensive: running as root makes every file the node creates
# root-owned, so `rm -rf ~/qadena` as the login user then fails on every entry, the next install
# refuses because it cannot overwrite what is there, and the enclave's own unix socket is left in
# sticky /tmp where only root can unlink it.  That last one is not theoretical -- see the stale
# socket handling in cmd/qadenad_enclave/enclave.go, which exists because of it.
#
# So: refuse only when the devices are genuinely out of reach, and say what to DO about it.  Joining
# the group is the fix; sudo is the workaround, and the message says what the workaround costs.
#
# The binary argument is optional so existing callers keep working; without it the check falls back
# to the chain enclave, which is what every runtime script is ultimately gating on.
needs_root_if_real_enclave() {
  name="$1"
  bin="${2:-$qadenabin/qadenad_enclave}"

  use_real_enclave "$bin" || return 0    # Q1 false: simulating, no device to open
  [[ $(id -u) -eq 0 ]]    && return 0    # already root, which opens them by definition
  sgx_usable_by_me        && return 0    # Q2 true: this is the normal, provisioned case

  if ! sgx_present; then
      echo "$name:  Error: this build is a real SGX enclave, but the SGX devices are not both present." >&2
      echo "$name:         enclave:    ${$(sgx_enclave_dev):-MISSING}" >&2
      echo "$name:         provision:  ${$(sgx_provision_dev):-MISSING}" >&2
      echo "$name:         Provisioning is required for ATTESTATION -- without it the enclave runs but" >&2
      echo "$name:         cannot quote, and the failure surfaces later as a rejected join." >&2
      echo "$name:         Install the in-kernel SGX driver (ubuntu/setup_qadena_build.sh)." >&2
      exit 1
  fi

  # Present but not ours.  Name ONLY the devices that are actually blocking, and only the groups
  # those devices belong to -- read from stat rather than assumed.
  #
  # The two devices routinely differ.  On one of the test machines /dev/sgx_enclave is mode 666 and
  # openable by anybody while /dev/sgx_provision is 660 root:sgx_prv, so the ONLY thing to join is
  # sgx_prv.  Telling that operator to join `sgx,sgx_prv` is advice that works but does not match
  # what is wrong, and advice that overstates the problem trains people to stop reading it.
  local d g blocked="" groups=""
  for d in $(sgx_enclave_dev) $(sgx_provision_dev); do
      [[ -r $d && -w $d ]] && continue
      g=$(stat -c %G "$d" 2>/dev/null)
      blocked="$blocked $d${g:+ (group $g)}"
      [[ -n $g ]] && groups="$groups $g"
  done
  groups=$(print -l ${=groups} | sort -u | paste -sd, -)

  echo "$name:  Error: $(id -un) cannot open:${blocked}" >&2
  echo "$name:         Fix (preferred): join the groups that own them, then log in again --" >&2
  echo "$name:             sudo usermod -aG $groups $(id -un)" >&2
  echo "$name:         Workaround: re-run with sudo.  Note that this makes every file the node" >&2
  echo "$name:         creates root-owned, including /tmp/qadena_*.sock in sticky /tmp, which only" >&2
  echo "$name:         root can then remove -- so the next unprivileged start will fail to bind." >&2
  exit 1
}

# as_enclave_owner <command...> -- run one command as whoever owns the enclave.
#
# The counterpart to needs_root_if_real_enclave, for callers that must NOT themselves become root.
# The test suites run as the login user and need to keep doing so: they write logs and use the
# keyring under $QADENAHOME, and running the whole suite as root would leave root-owned files
# behind for the next unprivileged run to trip over.
#
# But on SGX the enclave PROCESS and its unix socket belong to root, because `ego run` needs
# /dev/sgx_enclave.  So a suite that signals the enclave or talks to it gets EPERM:
#
#     kill 3152561 failed: operation not permitted
#     dial unix /tmp/qadena_50051.sock: connect: permission denied
#
# and reports "cannot SIGSTOP the enclave" or "cannot read the enclave's store hashes" -- both of
# which read as a BROKEN ENCLAVE rather than a permission boundary.  That cost a real diagnosis:
# enclave-rollback and enclave-crash both failed within two seconds on a healthy SGX node, which
# looks exactly like the regression those suites exist to catch.
#
# On a debug node the enclave runs unprivileged and this is a no-op, which is why the predicate is
# use_real_enclave rather than "am I on SGX hardware" -- a debug enclave on SGX hardware needs no
# sudo, and asking for it would prompt for a password in a suite that must not block.
# THE PREDICATE IS OWNERSHIP, not "is this a real enclave", and the difference matters in both
# directions.  A real SGX enclave does NOT inherently need root: setup_qadena_build.sh adds the
# login user to the sgx and sgx_prv groups, and a node started unprivileged then owns its own
# socket, where elevating would be pointless.  Equally, a node someone started with sudo needs it
# whether or not SGX is involved.  Asking who actually owns the process answers both without
# assuming a deployment style.
#
# sudo -n, not plain sudo: a suite that stops on an invisible password prompt looks like a hang, and
# these run unattended from run_regression_continually.sh.  Failing immediately with "a password is
# required" is a diagnosable message; blocking forever is not.
#
# The bracket classes in the patterns are not decoration -- see the pkill warning in
# A LOG PATH THIS USER CAN ACTUALLY WRITE, proven with a real write before anything relies on it.
#
# /tmp is sticky (1777): a file left there by an earlier run AS ROOT cannot be truncated by the
# login user.  A failed redirect means THE COMMAND NEVER RUNS -- and because the stale file is still
# readable, a later `tail` of that path prints the OLD run's output, which reads like a plausible
# current result.  Every artefact then agrees with a story that is not happening.
#
# That has now cost real time twice: once in 1st_node_bringup.sh (its trap 1, two wrong conclusions)
# and once in test_enclave_upgrade.sh, where a root-owned log from eleven days earlier made a build
# that never started look like a build that succeeded and then failed.  Hence a shared helper: the
# name carries the user (root's copy cannot collide), the file is removed first, and writability is
# PROVEN rather than assumed.
#
#   log=$(user_log_path enclave_upgrade_build) || exit 1
#
# Prints the path on success.  On failure prints nothing and returns 1, having explained on stderr
# what is wrong and the single command that fixes it.
user_log_path() {
    local base="$1"
    # `logfile`, NOT `path`.  In zsh `path` is the array form of PATH, so `local path=...` replaces
    # the command search path with that one string for the rest of the call and every EXTERNAL
    # command returns 127 -- while builtins keep working, so the function still returns a sensible
    # value and looks fine.  Here that silently disabled the `rm -f` below, which is the one thing
    # this helper exists to guarantee: a stale file of the same name is exactly what makes a command
    # that never ran look like one that ran and failed.  `stat` in the error path died the same way,
    # reporting every owner as "unknown".
    local logfile="${TMPDIR:-/tmp}/${base}.$(id -un).log"
    rm -f "$logfile" 2>/dev/null
    if ! : > "$logfile" 2>/dev/null; then
        print -u2 "cannot write $logfile (owner $(stat -c %U "$logfile" 2>/dev/null || echo unknown); /tmp is sticky)."
        print -u2 "A redirect that fails means the command never runs, while a stale file of the same"
        print -u2 "name makes it look like it did.  Remove it and re-run:"
        print -u2 "    sudo rm -f $logfile"
        return 1
    fi
    print -r -- "$logfile"
}

# ISSUE A FEE GRANT THAT BELONGS TO THE FOUNDATION, WITHOUT HOLDING THE FOUNDATION'S KEY.
#
#   grant_as_foundation <granter-addr> <grantee-addr> <allowed-messages-csv> [signer-key]
#
# A fee grant is signed by its GRANTER, so a grant drawn on the foundation must be signed by the
# foundation. That is fine in this harness, where one keyring holds every key -- and wrong in a real
# deployment, where SEC runs steps 1-3 and must never hold a foundation key. The three-step structure
# exists precisely to keep those apart.
#
# authz closes the gap: the foundation authorises SEC's admin key ONCE for
# /cosmos.feegrant.v1beta1.MsgGrantAllowance, and SEC then wraps each grant in a MsgExec. The
# allowance is the foundation's, the signature is SEC's, and SEC holds a revocable permission rather
# than a key.
#
#   VERITAS_SEC_ADMIN set   -> wrap in MsgExec, signed by that key, foundation pays for the MsgExec
#   unset                   -> sign directly as the granter (harness only; needs the granter's key)
#
# --generate-only on the inner message is not optional: authz resolves the grant on the INNER
# message's signer, so a message built with --from <sec key> names SEC as granter, matches no
# authorisation, and is rejected with ErrNoAuthorizationFound.
# THE FUNDING MODEL, SETTLED IN ONE PLACE.
#
# "foundation-sponsored" is the same thing the node bring-up calls it (add_full_node.sh
# --foundation-sponsored, testscripts/foundation_sponsor_node.sh): the foundation pays, by fee
# grant, and the party being onboarded never holds tokens.  VERITAS works exactly that way, so it
# uses the same word.
#
# IT IS SET HERE BECAUSE FOUR SCRIPTS DISAGREED ABOUT IT.  step_2 defaulted to banksend while
# step_3 and create_user.sh defaulted differently again -- so with the variable unset, step_2 sat
# in a `while` loop waiting for funds in a treasury the sponsored flow never fills, while step_3
# assumed sponsorship.  Only setup_veritas.sh exporting the value hid it.  One default, one place.
#
# "feegrant" is accepted as the old spelling so anything still exporting it keeps working.
: ${VERITAS_FUND_MODE:=foundation-sponsored}
[ "$VERITAS_FUND_MODE" = "feegrant" ] && VERITAS_FUND_MODE=foundation-sponsored
export VERITAS_FUND_MODE

grant_as_foundation() {
    local granter="$1" grantee="$2" msgs="$3" signer="${4:-${VERITAS_SEC_ADMIN:-}}"
    local gasflags=(--gas-prices "$minimum_gas_prices" --gas "$gas_auto" --gas-adjustment "$gas_adjustment")
    local out hash code tmp

    # Revoke first: a grantee holds at most ONE allowance per granter, so a wider grant cannot be
    # layered over a narrower one already left by create-wallet's own grantFee.
    if [ -n "$signer" ]; then
        tmp=$(mktemp)
        qadenad_alias tx feegrant revoke "$granter" "$grantee" --from "$granter" --generate-only \
            > "$tmp" 2>/dev/null || true
        [ -s "$tmp" ] && qadenad_alias tx authz exec "$tmp" --from "$signer" --fee-granter "$granter" \
            --yes --output json "${gasflags[@]}" >/dev/null 2>&1 || true
        rm -f "$tmp"
    else
        qadenad_alias tx feegrant revoke "$granter" "$grantee" --from "$granter" \
            --yes --output json "${gasflags[@]}" >/dev/null 2>&1 || true
    fi
    sleep 3

    if [ -n "$signer" ]; then
        tmp=$(mktemp)
        qadenad_alias tx feegrant grant "$granter" "$grantee" --allowed-messages "$msgs" \
            --from "$granter" --generate-only > "$tmp" 2>/dev/null || { rm -f "$tmp"; return 1; }
        out=$(qadenad_alias tx authz exec "$tmp" --from "$signer" --fee-granter "$granter" \
              --yes --output json "${gasflags[@]}" 2>&1); rm -f "$tmp"
    else
        out=$(qadenad_alias tx feegrant grant "$granter" "$grantee" --allowed-messages "$msgs" \
              --from "$granter" --yes --output json "${gasflags[@]}" 2>&1)
    fi

    hash=$(echo "$out" | grep '^{' | tail -1 | jq -r '.txhash // ""' 2>/dev/null)
    [ -n "$hash" ] || { echo "grant_as_foundation: no txhash for $grantee: $(echo "$out" | tail -1)" >&2; return 1; }
    qadenad_alias query wait-tx "$hash" --timeout 60s >/dev/null 2>&1 || true
    code=$(qadenad_alias query tx "$hash" --output json 2>/dev/null | jq -r '.code // "?"')
    [ "$code" = "0" ] || { echo "grant_as_foundation: $grantee failed on chain (code $code)" >&2; return 1; }
    return 0
}

# A KILLABLE UNIT FOR A SCRIPT-STARTED ENCLAVE.
#
# `ego run` is a launcher: it forks /opt/ego/bin/ego-host, and the enclave lives inside THAT.  A
# script that starts the launcher therefore holds a pid which is not the thing doing the work, so
# signalling it leaves the host running -- the same shape as the bug the in-process supervisor had
# before it grew Setpgid (x/qadena/keeper/enclave_supervisor.go).  stop_qadena.sh compensated with
# pattern kills across BOTH command lines plus a wait-and-escalate, which works but depends on the
# patterns continuing to match argv we do not control.
#
# The structural fix is the one the Go side already uses: put the launcher in its own PROCESS GROUP
# and signal the group.  Every descendant inherits the group id, whatever it is called.
#
# Getting a new process group from a script is the awkward part.  `setsid` does not exist on macOS,
# and zsh's monitor mode (`set -m`) fails outright with "can't change option: -m" when the script
# has no controlling terminal -- which is exactly how these run (ssh, nohup, PTY drivers).  perl is
# present by default on macOS and is Essential on Debian/Ubuntu, and setpgrp(0,0) followed by exec
# leaves the SAME pid as the group leader, so the caller's $! is both the pid and the pgid.
#
# Used as:   run_in_new_process_group cmd args... &
#            pgid=$!
# If perl is missing the command still runs -- just in the caller's group, with no pgid recorded,
# and stop_qadena.sh falls back to its pattern kills.
#
# IT ALSO RESTORES SIGINT, which is not incidental -- it is a bug fix.  A shell without job control
# sets SIGINT and SIGQUIT to SIG_IGN for every command started with `&` (POSIX), and exec PRESERVES
# an ignored disposition.  run_enclave_standalone.sh is itself started with `&` by add_full_node.sh
# and used to exec the enclave, so the enclave inherited SIG_IGN for SIGINT and could not shut down
# gracefully at all: stop_qadena.sh's SIGINT was silently discarded and the enclave only ever died
# at the 60s SIGKILL escalation.  That matches what was measured chasing the .140 socket handover --
# the SGX enclave still present 20s after the stop and gone by 80s.  Setting the disposition back to
# default before exec is what makes a clean stop possible; verify with:
#     kill -INT -- -$(cat $QADENAHOME/enclave.pgid)   # the enclave must exit, not sit there
run_in_new_process_group() {
    if command -v perl > /dev/null 2>&1 ; then
        exec perl -e '
            setpgrp(0,0) or die "setpgrp: $!\n";
            $SIG{INT} = $SIG{QUIT} = "DEFAULT";
            exec { $ARGV[0] } @ARGV or die "exec $ARGV[0]: $!\n"' -- "$@"
    fi
    print -u2 "run_in_new_process_group: no perl -- running in the caller's process group instead."
    print -u2 "    (stopping will fall back to pattern matching; see stop_qadena.sh)"
    trap - INT QUIT   # best effort at the same disposition reset; zsh may decline for a signal
    exec "$@"         # that was already ignored on entry, hence the SIGKILL escalation downstream
}

# Where run_enclave_standalone.sh records the group it started, for stop_qadena.sh to signal.
# Per-home, because two homes on one machine are two independent enclaves.
export qadena_enclave_pgidfile="$QADENAHOME/enclave.pgid"

# Members of process group $1 whose command line matches $2 -- prints "pid pgid command" lines and
# returns 0 only if there was at least one.
#
# A PGID IS NOT A CAPABILITY: pids and process-group ids are recycled, and a pgid file outlives the
# run that wrote it (a machine that lost power never got to clean it up).  `kill -- -$pgid` on a
# stale file signals whatever now owns that number, which on a busy machine is somebody else's job.
# So the group is only ever signalled after this confirms it still contains an enclave.
process_group_members() {
    local pgid="$1" pattern="$2" found
    [[ -n $pgid ]] || return 1
    found=$(ps -ax -o pid=,pgid=,command= 2>/dev/null | awk -v g="$pgid" -v p="$pattern" '$2==g && $0 ~ p {print}')
    [[ -n $found ]] || return 1
    print -r -- "$found"
}

# nth_node_bringup.sh.  A plain `pgrep -f qadenad_enclave` matches the shell running this very
# function when the suite was invoked over ssh.
as_enclave_owner() {
  # A DEBUG ENCLAVE NEVER NEEDS ELEVATION, and must never attempt it.  It runs as whoever started
  # the node -- us -- and a debug machine may have no sudo configured at all, so reaching for it
  # there would break runs that work today.  This is the FIRST check for that reason: everything
  # below is about real enclaves only.
  #
  # Gating on the BINARY rather than on the hardware is deliberate.  A debug enclave running on SGX
  # hardware still needs no privilege, which is the same distinction needs_root_if_real_enclave
  # draws and for the same reason.
  use_real_enclave "$qadenabin/qadenad_enclave" || { "$@"; return $? }

  # Already root: there is nothing to elevate to.
  [[ $(id -u) -eq 0 ]] && { "$@"; return $? }

  # A real enclave WE started needs no elevation either.  That is not hypothetical --
  # setup_qadena_build.sh puts the login user in the sgx and sgx_prv groups, so an SGX node can be
  # started unprivileged and then owns its own socket (see backlog item 30).
  local pid owner
  pid=$(pgrep -f "ego-host.*qadenad_enclav[e]" 2>/dev/null | head -1)
  if [[ -n "$pid" ]]; then
      owner=$(ps -o user= -p "$pid" 2>/dev/null | tr -d ' ')
      [[ -n "$owner" && "$owner" == "$(id -un)" ]] && { "$@"; return $? }
  fi

  # A real enclave owned by someone else -- or one we cannot identify, where guessing "no" would
  # reproduce the EPERM this function exists to fix.
  sudo -n "$@"
}

# confirm_tx <hash> [seconds] -- did this transaction land, and did it succeed?
#
# `query wait-tx` alone is NOT a reliable answer.  It SUBSCRIBES to a websocket event, so a
# transaction that was already included before the subscription was established never produces one
# and the command times out -- reporting failure for a transaction that succeeded.  A freshly started
# node makes that likely, because the first transactions are committed while the client is still
# connecting.
#
# That is not hypothetical: it failed setup_prerequisites.sh with "could not vote on proposal 2"
# while the proposal had in fact PASSED, and took the idempotency suite down with it on the re-run.
#
# So the event is treated as a fast path and the CHAIN as the authority: if waiting does not answer,
# ask what actually happened.
confirm_tx() {
    local hash="$1" secs="${2:-30}"

    [ -n "$hash" ] && [ "$hash" != "null" ] || { echo "confirm_tx: no transaction hash"; return 1; }

    qadenad_alias query wait-tx "$hash" --timeout "${secs}s" > /dev/null 2>&1

    # Poll regardless of how the wait turned out -- it may have missed the event, and it may also
    # have returned before the transaction was indexed.
    local code i
    for i in $(seq 1 "$secs"); do
        code=$(qadenad_alias query tx "$hash" --output json 2>/dev/null | jq -r '.code // empty' 2>/dev/null)
        [ -n "$code" ] && break
        sleep 1
    done

    if [ -z "$code" ]; then
        echo "confirm_tx: $hash never appeared on chain within ${secs}s"
        return 1
    fi
    if [ "$code" != "0" ]; then
        echo "confirm_tx: $hash failed with code $code: $(qadenad_alias query tx "$hash" --output json 2>/dev/null | jq -r '.raw_log // empty' 2>/dev/null)"
        return 1
    fi
    return 0
}

# tx_reject_code <cmd...> -- run a transaction that is EXPECTED TO FAIL and print the qadena code
# that actually rejected it, or 0 if the chain accepted it.
#
# WHY THE EXIT CODE OF `tx` CANNOT ANSWER THIS.  A message-level rejection surfaces in one of two
# places, and which one depends on load, not on policy:
#
#   CheckTx      the node refuses the transaction outright.  The CLI prints the code and exits
#                non-zero, and the transaction never enters a block.
#   execution    the transaction is INCLUDED IN A BLOCK and fails there.  Broadcast succeeded, so
#                the CLI exits ZERO and prints code: 0 -- the failure is only in the delivered
#                transaction's own result.
#
# Suites that asserted `if "$@"; then fail "it succeeded"` therefore reported a correctly-refused
# transaction as ACCEPTED whenever the chain was busy enough to admit it to a block first.  Measured
# on M1: the no-eKYC transfer was rejected with code 1158 in EVERY case, but the regression called it
# "allowed to transfer" in 10 of 27 cycles -- purely a function of where the rejection landed.  The
# same shape failed `credentials` 19 times and `uniqueness` 4 times.
#
# So ask the chain, in both places, in order.
tx_reject_code() {
    local out hash checktx delivered log
    out=$("$@" 2>&1) || true

    # CheckTx first: a hash is returned even for transactions refused here, so the code has to be
    # read before any wait -- waiting on one that never entered a block cannot terminate.
    checktx=$(print -r -- "$out" | strings | grep -oE '^code: [0-9]+' | head -1 | awk '{print $2}')
    if [[ -n "$checktx" && "$checktx" != "0" ]]; then
        print -r -- "$out" | strings | grep -oE 'codespace qadena code [0-9]+' | tail -1 | awk '{print $4}'
        return 0
    fi

    hash=$(print -r -- "$out" | strings | grep -oE 'txhash: [A-Fa-f0-9]+' | tail -1 | awk '{print $2}')

    # NOT BROADCAST AT ALL is a REJECTION, not an acceptance -- a failed `--gas auto` simulation is
    # the usual cause, and simulation runs the message, so it is the chain refusing it.  Report the
    # qadena code when the text carries one, and the sentinel "rejected-before-broadcast" when it
    # does not, because returning EMPTY here made callers say "the chain ACCEPTED it" about a
    # transaction that never existed.  That is how case 3 of test_credentials.sh was reported as a
    # policy failure while the credential's own Update Generation showed the update never applied.
    #
    # `tail -1`, not `head -1`, on the hash: these commands print more than one response, and taking
    # the first picked up the PREVIOUS transaction's hash -- which then resolved to a completely
    # unrelated tx and made the verdict nonsense.
    if [[ -z "$hash" ]] || ! print -r -- "$out" | strings | grep -qE 'txhash: [A-Fa-f0-9]{64}'; then
        local code
        code=$(print -r -- "$out" | strings | grep -oE 'codespace qadena code [0-9]+' | tail -1 | awk '{print $4}')
        print -r -- "${code:-rejected-before-broadcast}"
        return 0
    fi

    qadenad_alias query wait-tx "$hash" --timeout 60s > /dev/null 2>&1
    delivered=$(qadenad_alias query tx "$hash" --output json 2>/dev/null | jq -r '.code // 0' 2>/dev/null)
    if [[ "$delivered" == "0" ]]; then
        # ACCEPTED means the transaction landed AND executed cleanly.  Callers asserting a rejection
        # should also check that the state did not move: a code of 0 on a transaction that changed
        # nothing is a different bug from a policy that failed to refuse, and only the state can
        # tell them apart (Update Generation, in the credential case).
        print "0"
        return 0
    fi
    log=$(qadenad_alias query tx "$hash" --output json 2>/dev/null | jq -r '.raw_log // empty' 2>/dev/null)
    print -r -- "$log" | grep -oE 'codespace qadena code [0-9]+' | tail -1 | awk '{print $4}'
}

# wait_for_tx <broadcast-json> [label] -- check the broadcast BEFORE waiting for the transaction.
#
# THIS EXISTS BECAUSE THE OBVIOUS FORM HANGS FOREVER.  Every call site used to be
#
#     qadenad_alias ... query wait-tx $(echo "$RESP" | jq -r '.txhash') --timeout 30s
#
# and when the transaction was not broadcast at all -- a failed `--gas auto` simulation, most often
# -- $RESP is not JSON, `.txhash` is EMPTY, and that becomes `query wait-tx --timeout 30s` with no
# hash argument, which blocks indefinitely.  --timeout does not bound it.  A disbursement failure
# sat on that line for over seven minutes and stalled an entire regression run, and the error
# explaining it had already been printed and discarded.
#
# A hash is also returned for transactions REJECTED at CheckTx, which are never included in a block
# and so can never be found by waiting.  The code has to be read before the wait, not after it.
# EVERY FAILURE PATH PRINTS THE WORD "UNCONFIRMED", and that is a contract callers depend on.
# cadena_cli.sh `full` returns 0 no matter what fails inside it, so its exit code cannot be used to
# tell whether the transactions actually landed -- a suite could only assert on state afterwards and
# INFER success.  That inference is what let a stalled disbursement report PASS: the transaction had
# long since landed while the flow sat blocked on a wait that could never finish, so the state check
# found its record and saw nothing wrong.  A single grep for UNCONFIRMED gives suites the fact they
# could not otherwise get.
wait_for_tx() {
    local resp="$1" label="${2:-transaction}"

    local hash code
    hash=$(echo "$resp" | jq -r '.txhash // empty' 2>/dev/null)
    code=$(echo "$resp" | jq -r '.code // empty' 2>/dev/null)

    if [[ -z "$hash" ]]; then
        echo "wait_for_tx: UNCONFIRMED -- $label was never broadcast, no txhash in the response."
        echo "wait_for_tx: this is usually a failed gas simulation, whose error goes to STDERR"
        echo "wait_for_tx: while only stdout is captured -- so run the caller with 2>&1 to see it."
        echo "wait_for_tx: response was:"
        echo "$resp" | head -5
        return 1
    fi

    if [[ -n "$code" && "$code" != "0" ]]; then
        echo "wait_for_tx: UNCONFIRMED -- $label was REJECTED at CheckTx with code $code"
        echo "wait_for_tx: $(echo "$resp" | jq -r '.raw_log // empty' 2>/dev/null)"
        echo "wait_for_tx: it will never be included in a block, so it is not waited for."
        return 1
    fi

    # The WAIT ITSELF CAN FAIL, and that was previously swallowed too: a timeout, or a transaction
    # that failed in DeliverTx, left the flow continuing as though the write had happened.
    if ! qadenad_alias --node $QADENA_NODE query wait-tx "$hash" --timeout 30s; then
        echo "wait_for_tx: UNCONFIRMED -- $label ($hash) was not confirmed within 30s."
        echo "wait_for_tx: it was accepted at CheckTx, so it may still land later; nothing that"
        echo "wait_for_tx: depends on it has happened yet."
        return 1
    fi
}

is_zero() {
  val="$1"

  # normalize empty/null
  if [ -z "$val" ] || [ "$val" = "null" ]; then
    return 0
  fi

  eps="0.000000000000001"
  if echo "v=($val); if (v<0) v=-v; v < $eps" | bc -l | grep -q 1; then
    return 0
  fi
  return 1
}

is_greater_than() {
  a="$1"
  b="$2"

  if [ -z "$a" ] || [ "$a" = "null" ]; then
    a=0
  fi
  if [ -z "$b" ] || [ "$b" = "null" ]; then
    b=0
  fi

  if echo "$a > $b" | bc -l | grep -q 1; then
    return 0
  fi
  return 1
}

# extract minimum-gas-prices from config.yml
# check if config.yml exists
set_min_gas_price() {

  fallback=false

  # if qadenad_alias is not executable, then return fallback
  if ! command -v qadenad_alias > /dev/null 2>&1; then
    #echo "qadenad_alias not found, will try to get minimum gas prices from config.yml"
    fallback=true
  fi

  if ! command -v jq > /dev/null 2>&1; then
    #echo "jq not found, will try to get minimum gas prices from config.yml"
    fallback=true
  fi

  local params_json
  params_json=$(qadenad_alias query feemarket params --output json 2>/dev/null)
  if [[ "$params_json" == "" ]] ; then
    #echo "feemarket params not found, will try to get minimum gas prices from config.yml"
    fallback=true
  fi

  if [ "$fallback" = true ]; then
    #echo "Using fallback minimum gas prices from config.yml"
    if [[ ! -f $QADENAHOME/config/config.yml ]]; then
        minimum_gas_prices="500000000aqdn"
        export minimum_gas_prices
        return
    fi
    #
    # THE DENOM IS ONLY APPENDED IF IT IS NOT ALREADY THERE.  config.yml carries a full coin string
    # ("500000000aqdn"), not a bare number, so appending unconditionally produced
    #
    #     expected only native token aqdn for fee, but got 54683000000000aqdnaqdn
    #
    # and every transaction using $minimum_gas_prices was rejected at broadcast.  It hid well: this
    # branch only runs when the feemarket query fails, which is exactly what happens when
    # regression.sh sources this file at the start of a --from-genesis run -- before the chain it is
    # about to build exists.  So the fallback, and therefore the bug, is guaranteed on precisely the
    # runs that build a new chain, and absent on every run against a live one.
    minimum_gas_prices="$(dasel -f $QADENAHOME/config/config.yml 'validators.first().app.minimum-gas-prices')"
    case "$minimum_gas_prices" in
        *aqdn) ;;
        *) minimum_gas_prices="${minimum_gas_prices}aqdn" ;;
    esac

    export minimum_gas_prices
    #echo "Found minimum gas prices: $minimum_gas_prices"
    return
  fi

  local min_gas_price
  local base_fee
  min_gas_price=$(echo "$params_json" | jq -r '.params.min_gas_price // 0')
  base_fee=$(echo "$params_json" | jq -r '.params.base_fee // 0')

  #echo "min_gas_price: $min_gas_price"
  #echo "base_fee: $base_fee"

  if is_zero "$min_gas_price" && is_zero "$base_fee"; then
    #echo "feemarket params are effectively zero, will try to get minimum gas prices from config.yml"
    fallback=true
  fi

  # take the max of min_gas_price and base_fee using bc
  if is_greater_than "$min_gas_price" "$base_fee"; then
    minimum_gas_prices="$min_gas_price"
  else
    minimum_gas_prices="$base_fee"
  fi

  # add 10% buffer
  minimum_gas_prices=$(echo "$minimum_gas_prices * 1.1" | bc)

  # add 1
  minimum_gas_prices=$(echo "$minimum_gas_prices + 1" | bc)

  #echo "Using minimum gas prices: $minimum_gas_prices"
  minimum_gas_prices="${minimum_gas_prices}aqdn"

  export minimum_gas_prices
  return
}

set_min_gas_price
gas_adjustment=1.5
gas_auto=auto

# export
export gas_adjustment

# COMMON FUNCTIONS
# Function to increment the number in a string
increment_id() {
  local current_val
  current_val=$(<"$1") # Read file content

  # Extract numeric part and increment
  local prefix="${current_val%%[0-9]*}" # Get non-numeric prefix
  local number="${current_val##*[!0-9]}" # Get numeric part
  local new_number=$((10#$number + 1))  # Increment with base 10

  # Format to maintain leading zeros if necessary
  local new_value="${prefix}$(printf "%03d" "$new_number")"

  # Write back to the file
  echo -n "$new_value" > "$1"

  echo "$new_value"
}

# Function to increment the version
increment_version() {
  local current_val
  current_val=$(<"$1") # Read file content

  # Extract Major, Minor, and Build numbers
  local MAJOR=$(echo "$current_val" | cut -d. -f1)
  local MINOR=$(echo "$current_val" | cut -d. -f2)
  local BUILD=$(echo "$current_val" | cut -d. -f3)

  # Increment the Build number
  local NEW_BUILD=$((BUILD + 1))

  # Construct the new version
  local NEW_VERSION="$MAJOR.$MINOR.$NEW_BUILD"

  # Write back to the file
  echo -n "$NEW_VERSION" > "$1"

  echo "$NEW_VERSION"
}

# WHICH CHAIN-RESTARTING SUITES ARE UNSAFE ON THIS NODE, decided on evidence rather than by flag.
#
# SHARED, because both regression.sh and run_regression_continually.sh need the same answer and a
# second copy is a second place for it to drift.  A bare regression.sh used to have no guard at all:
# on a fleet whose primary holds >= 1/3 of voting power, enclave-crash stopped the only node that
# could keep the chain committing and halted it -- while the soak, running the same suites, refused
# for exactly that reason.
#
#
# --no-auto-skip turns all of this off, because a deliberate "I want to run the disruptive suite on
# this fleet, I know what it does" has to remain expressible.
topology_skips() {
    local n_peers total mine pct out=()

    n_peers=$(curl -s --max-time 5 localhost:26657/net_info 2>/dev/null | jq -r '.result.n_peers // 0' 2>/dev/null)
    [ -n "$n_peers" ] || n_peers=0

    # ASK COMETBFT WHAT THIS NODE IS, rather than matching monikers against the staking list.
    #
    # /status reports validator_info.voting_power for THIS node: 0 means it is a full node, and a
    # full node cannot halt anything by stopping itself.  An earlier version looked this node up in
    # the bonded set by moniker, which was wrong twice over -- config.toml's moniker need not equal
    # the validator's description.moniker, and a FULL NODE is absent from that list entirely, so
    # "not found" fell into the unknown branch and skipped every disruptive test on a node where
    # all of them are safe.  "I am not a validator" and "I could not tell" are different answers
    # and only the second one should fail closed.
    mine=$(curl -s --max-time 5 localhost:26657/status 2>/dev/null \
           | jq -r '.result.validator_info.voting_power // empty' 2>/dev/null)
    total=$(curl -s --max-time 5 localhost:26657/validators 2>/dev/null \
            | jq -r '[.result.validators[]?.voting_power | tonumber] | add // empty' 2>/dev/null)

    if [ -z "$mine" ]; then
        echo "  could not read this node's voting power; assuming it matters and skipping the disruptive tests" >&2
        out+=(enclave-rollback enclave-crash)
    elif [ "$mine" = "0" ]; then
        echo "  this node is a FULL NODE (voting power 0) -- stopping it cannot halt the chain" >&2
    elif [ -z "$total" ] || [ "$total" = "0" ]; then
        echo "  this node is a validator but the total voting power could not be read; assuming it matters" >&2
        out+=(enclave-rollback enclave-crash)
    else
        pct=$(echo "scale=4; $mine * 100 / $total" | bc 2>/dev/null)
        if [ "$(echo "$pct > 33.4" | bc 2>/dev/null)" = "1" ]; then
            echo "  this node holds ${pct}% of voting power -- stopping it HALTS the chain" >&2
            out+=(enclave-rollback enclave-crash)
        else
            echo "  this node holds ${pct}% of voting power -- below 1/3, a self-stop costs only this node" >&2
        fi
    fi

    # ENCLAVE-ROLLBACK IS NOT SKIPPED FOR HAVING PEERS, and that is deliberate.
    #
    # It used to be, on the grounds that "the networked branch asserts against an unset $bal_after".
    # That was true and it was a TEST BUG, not a property of the chain: the rollback and the
    # re-convergence both worked, and the assertion compared the correct re-synced balance against
    # an empty variable that was never assigned.  Skipping routed around it, so the branch that
    # matters most on a fleet had never run once.  $bal_after is now captured in
    # test_enclave_rollback.sh; a minority node must be able to roll back on its own and catch back
    # up, and this is where that gets proven.
    #
    # The voting-power rule above still applies: at >= 1/3 the suite is skipped with enclave-crash,
    # because rolling back a node the quorum needs and restarting it alone manufactures a fork.

    # dedupe, comma-join
    printf '%s\n' "${out[@]}" | sort -u | paste -sd, -
}

# function to detect if all of the qadena processes are running

# BRACKET-CLASS THE -f PATTERNS, OR THIS MATCHES THE COMMAND THAT CALLED IT.
#
# `pgrep -f` tests the whole command line of every process, including the shell running this
# script and any ssh command that carried the words along.  The two ego-host patterns were
# unbracketed, so running anything whose command line happened to contain "ego-host" and
# "qadenad_enclave" -- a deploy one-liner, a diagnostic, an ssh invocation -- made this report
# "Qadena is running" when nothing was.  start_qadena.sh then refused to start with "Qadena is
# already running" and the node stayed DOWN.  Reproduced 2026-08-23: pgrep returned the pid of
# the very bash that was asking.
#
# `[e]go-host` matches the string "ego-host" but the literal text "[e]go-host" in a command line
# does not match it, so the pattern can no longer find ITSELF -- which covers the case that bit us,
# an ssh command or script carrying this very pgrep.  Same trap and same fix as
# 1st_node_bringup.sh:35, and trap 8 of the fleet bringup.
#
# WHAT THIS STILL DOES NOT FIX: a command line that contains "ego-host" and "qadenad_enclave" for
# unrelated reasons -- a deploy one-liner naming both -- would still match, because -f tests the
# whole command line and cannot tell a mention from a process.  The airtight version is the one in
# enclave_lib.sh, which reads `ps` and filters explicitly (`!/awk/ && !/grep/`) for exactly this
# reason.  Left as bracketing here because it is the smallest change that fixes the observed
# failure and keeps the matching semantics identical for real processes.
#
# The -x checks need no bracketing: they match the executable NAME exactly, so a shell can never
# satisfy them.  Output goes to /dev/null on every branch -- these two used to print their
# matches, which is how a false positive looked like real evidence of a running node.
# The unit's ActiveState, or "absent" when this node is not systemd-managed.  One word, so callers
# can print it or compare it without parsing systemctl's prose.
qadena_unit_state() {
  qadena_systemd_managed || { echo "absent"; return 0; }
  command -v systemctl >/dev/null 2>&1 || { echo "absent"; return 0; }
  systemctl show -p ActiveState --value qadena 2>/dev/null || echo "unknown"
}

# What every start/stop/restart message should carry, so an operator can tell at a glance whether
# systemd will have opinions about what they just did -- notably Restart=on-failure, which can
# bring a node back seconds after a direct kill "worked".
qadena_supervision_tag() {
  if qadena_systemd_managed; then
    echo "(systemd supervised: qadena.service $(qadena_unit_state))"
  else
    echo "(not systemd supervised)"
  fi
}

# THE RETURN VALUE IS PROCESS TRUTH, DELIBERATELY, AND SYSTEMD ONLY INFORMS THE MESSAGE.
#
# It is tempting to answer this with `systemctl is-active`, and that would be wrong in both
# directions.  A node can run OUTSIDE the unit -- restart_qadena.sh and run.sh start one directly,
# and the unit may be installed while a node is already up -- so an inactive unit does not mean an
# idle box.  And run.sh calls this as the unit's OWN ExecStart on its way out (see its "belt and
# braces" block), where the unit is still active and a systemd-based answer would have the node
# detect itself and try to stop the service currently executing the line.
#
# So: pgrep decides, systemd explains.  The disagreement cases are the ones worth naming out loud,
# because they are exactly the states that make a stop or start look like it misbehaved.
is_qadena_running() {
  local unit procs=1
  unit=$(qadena_unit_state)
  if pgrep -x qadenad >/dev/null ||
     pgrep -x qadenad_enclave >/dev/null ||
     pgrep -af '[e]go-host.*qadenad_enclave' >/dev/null ||
     pgrep -af '[e]go-host.*signer_enclave' >/dev/null ||
     pgrep -x signer_enclave >/dev/null; then
    procs=0
  fi

  if [[ $procs -eq 0 ]]; then
    case "$unit" in
      absent)   echo "Qadena is running (not systemd supervised)" ;;
      active)   echo "Qadena is running (systemd supervised)" ;;
      # Processes with no active unit: they escaped the cgroup, or were started by hand.  systemd
      # will NOT stop these for you, which is why the direct kills below it still exist.
      *)        echo "Qadena is running OUTSIDE the systemd unit (qadena.service $unit)" ;;
    esac
    return 0
  else
    case "$unit" in
      absent)   echo "Qadena is not running" ;;
      # An active unit with no processes is a node between restarts -- Restart=on-failure is very
      # likely about to start one, so "not running" is true only for this instant.
      active|activating)
                echo "Qadena is not running, but qadena.service is $unit (it may come back)" ;;
      *)        echo "Qadena is not running (systemd supervised: qadena.service $unit)" ;;
    esac
    return 1
  fi
}

banner() {
  local msg="$*"
  local content=" $msg "
  local border
  border="$(printf '%*s' $(( ${#content} + 2 )) '' | tr ' ' '-')"
  echo "$border"
  echo "|$content|"
  echo "$border"
}

run_cmd() {
  local cmd="$*"
  local wrap_width=80
  local wrapped
  local maxlen=0
  local line
  local border
  local i=0

  wrapped="$(echo "$cmd" | fold -s -w "$wrap_width")"

  while IFS= read -r line; do
    if (( ${#line} > maxlen )); then
      maxlen=${#line}
    fi
  done <<< "$wrapped"

  border="$(printf '%*s' $(( maxlen + 6 )) '' | tr ' ' '*')"
  echo "$border"

  while IFS= read -r line; do
    i=$(( i + 1 ))
    if (( i == 1 )); then
      printf '* > %-*s *\n' "$maxlen" "$line"
    else
      printf '*   %-*s *\n' "$maxlen" "$line"
    fi
  done <<< "$wrapped"

  echo "$border"
  echo "Results:"
  eval "$cmd"
}

run_cmd_capture() {
  local cmd="$*"
  local wrap_width=80
  local wrapped
  local maxlen=0
  local line
  local border
  local i=0

  wrapped="$(echo "$cmd" | fold -s -w "$wrap_width")"

  while IFS= read -r line; do
    if (( ${#line} > maxlen )); then
      maxlen=${#line}
    fi
  done <<< "$wrapped"

  border="$(printf '%*s' $(( maxlen + 6 )) '' | tr ' ' '*')"
  echo "$border" >&2

  while IFS= read -r line; do
    i=$(( i + 1 ))
    if (( i == 1 )); then
      printf '* > %-*s *\n' "$maxlen" "$line" >&2
    else
      printf '*   %-*s *\n' "$maxlen" "$line" >&2
    fi
  done <<< "$wrapped"

  echo "$border" >&2
  echo "Results:" >&2
  eval "$cmd"
}
