#!/bin/zsh
#
# Install or upgrade a Qadena node from a package built by buildscripts/package_release.sh.
#
# ON A TARGET MACHINE, which has nothing but the download:
#
#   tar xzf qadena-full-1.1.8-abc1234.tar.gz
#   ./qadena-full-1.1.8-abc1234/install.sh
#
# RUN IT AS THE USER WHO WILL OWN THE NODE -- not with sudo.  Installing writes only into that
# user's ~/qadena; nothing here needs root.  This used to say `sudo ./install.sh`, and following
# that advice on a provisioned machine leaves the whole node home owned by root, which breaks every
# command the operator later types: `qadenad q ...` cannot read its own 0600 config/client.toml, and
# `rm -rf ~/qadena` fails entry by entry.  See setup_env.sh's needs_root_if_real_enclave -- ROOT IS
# NOT A QADENA REQUIREMENT; opening the SGX devices is a group membership question, which
# setup_qadena_build.sh already arranges.  Use sudo only if this user cannot open /dev/sgx_* and you
# cannot fix that first; the install still works, and it hands the home back at the end.
#
# There is no git checkout, no build tree and no toolchain on that machine, and this script needs
# none: it is shipped inside the package as install.sh and sources nothing.  ego is required for an
# SGX package, because a node cannot start an ego-signed enclave without it -- and NOT required for a
# debug package, which is the only way the non-SGX path can work at all (ego is an amd64-only .deb).
#
# From a checkout, pointing at an archive works too:
#
#   scripts/install_release.sh <archive.tar.gz> [--wait-active[=SECONDS]] [--restart] [--force]
#                                               [--home DIR] [--no-prune]
#
# PRUNING IS ON BY DEFAULT for scripts/ and testscripts/: a script deleted upstream is deleted here
# too, so "installed" and "the current release" cannot drift apart.  Copying alone only ever adds,
# and a dead script is worse than a missing one because it still runs when someone types its name.
# Pruned files are backed up like any replaced file, and --no-prune turns it off.  bin/ is never
# pruned -- the measurement-suffixed enclaves must all stay on disk for upgrades to hand over.
#
# ONE SCRIPT, BOTH JOBS.  It works out for itself whether this machine needs a first INSTALL or an
# UPGRADE, because the difference is observable -- a machine with no qadenad and no sealed enclave
# state has nothing to preserve and no chain to consult, and one that has them has both.  Asking the
# operator to classify their own machine correctly is how you get an "install" run against a live
# validator.
#
#   INSTALL   nothing here yet.  Everything is written, the enclave is made current, and the node is
#             left ready to join.  No chain queries: there is no binary to query with and no home to
#             query from, and nothing on this machine could be harmed by a wrong answer.
#
#   UPGRADE   a node already exists.  The new enclave is STAGED next to the running one under its
#             measurement (a new filename, so the running binary is never written over), the chain is
#             consulted, and the switch happens only once the new identity is ACTIVE.  With
#             --wait-active the script waits for that itself and then performs the whole cutover:
#             stop, install, activate, and with --restart, start again.
#
# WHY IT WAITS RATHER THAN JUST REFUSING.  A new enclave identity has to be registered by governance
# and then PROMOTED to active, which happens on the proposer's enclave at its first UpdateHeight
# after a restart.  Registration and activation are minutes apart, so on a fleet the natural
# operation is "roll this out when the chain is ready", not "come back later and check".
#
# NOTHING IS EVER SILENTLY OVERWRITTEN.  Every destination this script writes is on an explicit
# allow-list; a package containing anything else is refused rather than unpacked.  Files that already
# exist and would change are copied into $QADENAHOME/backup/<timestamp>/ first.  config.yml is
# treated as OPERATOR-OWNED: a differing one is written beside the existing file as config.yml.new
# and never on top of it, because it carries minimum-gas-prices that a node operator may have tuned.
#
# NODE-SPECIFIC STATE IS NEVER TOUCHED: genesis.json, node_key.json, priv_validator_key.json,
# app.toml, config.toml, data/, keyring and the sealed enclave_params_<id>.json all stay exactly as
# they are.  Sealed state migrates via this node's OWN old enclave at the next start -- it is never
# copied between machines.

# STANDALONE BY DESIGN.  This script is shipped INSIDE the package as install.sh, so on a target
# machine there is no git checkout, no setup_env.sh in a sibling directory, and no build tree to
# infer anything from -- which is the whole point of distributing a package.  It therefore derives
# everything it needs itself and sources nothing.

# SELF-REPLACEMENT GUARD -- deliberately the first thing this script does.
#
# This script installs the package's scripts/ directory, and that directory CONTAINS THIS SCRIPT.
# So it overwrites its own file while zsh is still reading it.  zsh does not load a script into
# memory: it reads incrementally, keeping a byte offset and refilling as it goes.  Replace the file
# mid-run and the next read comes from the NEW file at the OLD offset.
#
# That was harmless for this script's entire life only because the installed copy had always been
# byte-identical to the packaged one -- the offset then lands on the same code and nothing is
# observable.  The first time the two differed IN LENGTH, the read landed mid-statement and zsh
# died with "parse error near", half-way through an install that had ALREADY STOPPED THE NODE.
# Observed 2026-08-25 on M1: qadenad installed, scripts/ installed, then the parse error, and the
# node was left down because the restart is further down this file.
#
# The hazard was already known here for a DIFFERENT file -- see the "run.sh re-reads its own script
# by byte offset" branch further down -- it had simply never been applied to this script itself.
#
# Re-exec from a private copy; the original may then be replaced freely.  $0 is restored to the real
# path afterwards so --help (which prints this script's own comments) and the invocation hints near
# the end keep naming the file the operator actually ran, not a temp copy.
if [[ -z "$QADENA_INSTALL_REEXEC" ]]; then
    _self=$(mktemp "${TMPDIR:-/tmp}/install_release.XXXXXX") \
        && cp "$0" "$_self" \
        && chmod +x "$_self" \
        || { echo "install: cannot make a private copy of $0 to re-exec from" >&2; exit 1; }
    QADENA_INSTALL_REEXEC="${0:A}" exec "$_self" "$@"
fi
_self_copy="$0"                   # the temp copy we are running from; removed by the traps
0="$QADENA_INSTALL_REEXEC"        # zsh permits this, and it keeps every $0 below meaningful
unset QADENA_INSTALL_REEXEC       # do not leak the marker into start_qadena.sh and friends
trap 'rm -f "$_self_copy"' EXIT INT TERM

SCRIPT_DIR="${0:A:h}"

set -e

archive=""
wait_active=0
wait_secs=1800
restart=0
force=0
home_override=""
prune=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --wait-active)    wait_active=1; shift ;;
    --wait-active=*)  wait_active=1; wait_secs="${1#*=}"; shift ;;
    --restart)        restart=1; shift ;;
    --force)          force=1; shift ;;
    --no-prune)       prune=0; shift ;;
    --home)           [[ -n "$2" && "$2" != --* ]] || { echo "--home requires a directory"; exit 1; }
                      home_override="$2"; shift 2 ;;
    --help)
      sed -n '2,55p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) archive="$1"; shift ;;
  esac
done

fail() { echo ""; echo "install: $1" >&2; exit 1; }
mval() { grep "^$1:" "$stage/manifest.txt" 2>/dev/null | awk '{print $2}'; }

# WHERE THE NODE LIVES.  Under sudo, $HOME is root's, and installing a node into /root is a mistake
# that is tedious to undo -- the enclave needs root to run, so sudo is the normal case, not the
# exception.  Resolve the invoking user's home instead, exactly as setup_env.sh does.
if [[ -n "$home_override" ]]; then
    QADENAHOME="${home_override:A}"
elif [[ -n "$SUDO_USER" ]]; then
    QADENAHOME="$(getent passwd "$SUDO_USER" | cut -d: -f6)/qadena"
else
    QADENAHOME="$(cd ~ && pwd)/qadena"
fi
export QADENAHOME
qadenabin="$QADENAHOME/bin"
qadenascripts="$QADENAHOME/scripts"
export LD_LIBRARY_PATH="$qadenabin:$LD_LIBRARY_PATH"
echo "node home: $QADENAHOME"

# WHAT THE TARGET MACHINE MUST ALREADY HAVE.  ego is required for an SGX package and ONLY for one:
# qadenad runs the ego-signed enclave under `ego run` and derives the measurement ids from ego for
# its init-enclave registration.  A debug enclave is a plain Go binary that reports those ids itself
# (-unique-id / -signer-id), and a machine installing a debug package needs no ego at all -- which is
# what makes the debug path usable, since ego ships as an amd64-only .deb and cannot be installed on
# ARM under any circumstances.
#
# SO THE REQUIREMENT CANNOT BE DECIDED HERE.  It depends on what is IN the package, and the package
# has not been unpacked yet.  It is enforced in section 1, once the manifest has said which kind of
# enclave arrived -- still before anything is written, which is what "say so now" was protecting.
prereq_hint() {
    # The package ships ubuntu/setup_qadena_build.sh precisely so a bare machine can fix this
    # itself.  Point at the copy that travelled with this package, not at a checkout that may not
    # exist here.
    # $SCRIPT_DIR/ubuntu when run from an unpacked package, ../ubuntu when run from a checkout.
    for d in "$SCRIPT_DIR/ubuntu" "$SCRIPT_DIR/../ubuntu"; do
        if [[ -f "$d/setup_qadena_build.sh" ]]; then
            echo "       sudo ${d:A}/setup_qadena_build.sh"
            return 0
        fi
    done
    echo "       run ubuntu/setup_qadena_build.sh from the qadena source tree"
}

missing=""
for t in jq curl dasel; do
    command -v "$t" > /dev/null 2>&1 || missing="$missing $t"
done
if [[ -n "$missing" ]]; then
    echo "  NOTE: missing:$missing -- needed to JOIN a chain (add_full_node.sh,"
    echo "        convert_to_validator.sh), not to install.  Install before joining:"
    prereq_hint
fi

# EITHER an archive to unpack, OR this script sitting inside an already-unpacked package.  The second
# form is what a target machine actually does: untar, run ./install.sh, done.
if [[ -z "$archive" && -f "$SCRIPT_DIR/manifest.txt" ]]; then
    stage="$SCRIPT_DIR"
    echo "package: $stage (already unpacked)"
else
    [[ -n "$archive" ]] || fail "no archive given, and no manifest.txt beside this script.
       Usage:  install_release.sh <archive.tar.gz>
       or:     tar xzf <archive.tar.gz> && <extracted-dir>/install.sh"
    [[ -f "$archive" ]] || fail "no such archive: $archive"
    archive="${archive:A}"
    stage=$(mktemp -d) || fail "could not create a staging directory"
    # Replaces the self-copy trap set at the top -- zsh traps are NOT additive, so this one has to
    # take over both jobs or the private copy leaks into /tmp on every run.
    trap 'rm -rf "$stage"; rm -f "$_self_copy"' EXIT INT TERM
    tar -xzf "$archive" --strip-components=1 -C "$stage" \
        || fail "could not extract $archive"
    [[ -f "$stage/manifest.txt" ]] || fail "$archive has no manifest -- is it a qadena release package?"
fi

echo "=== package ==="
sed 's/^/  /' "$stage/manifest.txt"

# ---------------------------------------------------------------------------------------------
# 1. the contents are what the manifest claims, and nothing else
# ---------------------------------------------------------------------------------------------
echo ""
echo "=== 1. contents ==="
( cd "$stage" && sha256sum -c sha256sums.txt > /dev/null 2>&1 ) \
    || fail "checksum mismatch -- the archive is corrupt or was tampered with"
echo "  checksums ok"

# THE ALLOW-LIST.  A package is a thing that arrives from elsewhere, so what it may write has to be
# decided here rather than by whoever built it.  config/ is the dangerous one: genesis.json,
# priv_validator_key.json and node_key.json all live in the same directory as the two files that are
# legitimately shipped, and quietly restoring any of them would destroy the node's identity or its
# view of the chain.
# NOT `read -r _ path`.  In zsh `path` is the array tied to $PATH, so reading into it replaces the
# command search path with "bin/qadenad" and every command after this loop is not found.
while read -r _sum entry; do
    case "$entry" in
        bin/qadenad|bin/qadenad_enclave|bin/signer_enclave|bin/libwasmvm*.so) ;;
        bin/cosmovisor) ;;
        scripts/*|testscripts/*|test_data/*) ;;
        config/config.yml|config/public.pem|config/node_params.json) ;;
        # Carried for the operator to run by hand; this script points at it but never runs it, and
        # never copies it into the node home.
        ubuntu/*) ;;
        *) fail "the package contains '$entry', which this installer will not write.
       Only binaries, scripts, testscripts, config.yml and public.pem are installable.  Node
       identity and chain state are never distributed." ;;
    esac
done < "$stage/sha256sums.txt"
echo "  every path is installable"

# WHICH IDENTITY MECHANISM THIS PACKAGE USES -- the PACKAGE's property, not this machine's.  An SGX
# package carries an ego-signed enclave identified by its measurement; a debug package carries a
# plain Go binary identified by the go:embed-ed placeholder it prints for itself.  Both must match
# what the chain's genesis recorded or every enclave-to-enclave call fails closed, so both are
# verified here -- the check is the same shape, only the reader differs.
#
# Packages built before this key existed are SGX by construction: the debug path could not be
# packaged at all, because packaging refused to run without ego.
# A PACKAGE WITH NO ENCLAVE HAS NO IDENTITY TO CHECK, and that is now a real case: an
# enclave-unchanged release packaged with --only chain,... carries qadenad and nothing else.  The
# absent-key default below reads "old package, therefore SGX", which was sound when the only way to
# lack the key was to predate it -- but a chain-only package lacks it because there is no enclave,
# and defaulting it to SGX then demands ego on a debug fleet and refuses an install that would have
# been perfectly correct.  Distinguish the two before defaulting: no qadenad_enclave.* keys at all
# means no enclave, not an old package.
if ! grep -q '^qadenad_enclave\.' "$stage/manifest.txt" 2>/dev/null; then
    identity_mode=none
    echo "  enclave identity: n/a -- this package carries no enclave (chain-only release)"
else
    identity_mode=$(mval qadenad_enclave.identity_mode)
    [[ -n "$identity_mode" ]] || identity_mode=sgx
    echo "  enclave identity: $identity_mode"
fi

if [[ "$identity_mode" == "sgx" ]]; then
    command -v ego > /dev/null 2>&1 || fail "this package carries an ego-signed (SGX) enclave, and ego
       is not installed here.  qadenad runs the enclave under 'ego run' and reads its measurement
       ids from ego, so this machine could not run the node even once installed.

       This package ships the setup script that installs it, along with the SGX quote
       provider, the PCCS configuration and the sgx/sgx_prv group membership:
$(prereq_hint)"
fi

# read_unique / read_signer <binary> -- an enclave binary's identity, by the package's mechanism.
#
# THE TWO ENCLAVES SPELL THE DEBUG FLAGS DIFFERENTLY: qadenad_enclave takes -unique-id / -signer-id,
# signer_enclave takes -query-unique-id / -query-signer-id.  Both are tried; the wrong one makes Go's
# flag package print "flag provided but not defined" to stderr and exit 2 without starting anything,
# so a miss yields no stdout rather than a plausible-looking wrong answer.
debug_id_of() {
    local b="$1" which="$2" f out=""
    for f in "-$which-id" "-query-$which-id"; do
        out=$("$b" "$f" 2>/dev/null | tail -1)
        if [[ -n "$out" && "$out" != *[[:space:]]* ]]; then
            printf "%s" "$out"
            return 0
        fi
    done
    return 1
}
read_unique() {
    if [[ "$identity_mode" == "sgx" ]]; then ego uniqueid "$1" 2>/dev/null | tail -1
    else debug_id_of "$1" unique || true; fi
}
read_signer() {
    if [[ "$identity_mode" == "sgx" ]]; then ego signerid "$1" 2>/dev/null | tail -1
    else debug_id_of "$1" signer || true; fi
}

new_encl="$stage/bin/qadenad_enclave"
new_unique=""; new_signer=""; new_version=""
if [[ -f "$new_encl" ]]; then
    chmod +x "$new_encl"
    new_unique=$(read_unique "$new_encl")
    new_signer=$(read_signer "$new_encl")
    new_version=$("$new_encl" -version 2>&1 | head -1)
    # The checksum proves the bytes arrived intact; the MEASUREMENT is what the chain actually
    # accepts, so verify the binary measures what the manifest promised.
    [[ "$new_unique" == "$(mval qadenad_enclave.unique_id)" ]] \
        || fail "qadenad_enclave measures $new_unique but the manifest says $(mval qadenad_enclave.unique_id)"
    echo "  qadenad_enclave measures $new_unique"
fi
if [[ -f "$stage/bin/signer_enclave" ]]; then
    chmod +x "$stage/bin/signer_enclave"
    s=$(read_unique "$stage/bin/signer_enclave")
    [[ "$s" == "$(mval signer_enclave.unique_id)" ]] \
        || fail "signer_enclave measures $s but the manifest says $(mval signer_enclave.unique_id)"
    echo "  signer_enclave measures $s"
fi

# ---------------------------------------------------------------------------------------------
# 2. install or upgrade?
# ---------------------------------------------------------------------------------------------
echo ""
echo "=== 2. what this machine needs ==="
cur_encl="$qadenabin/qadenad_enclave"
mode="install"
if [[ -x "$qadenabin/qadenad" || -x "$cur_encl" ]]; then
    mode="upgrade"
fi

node_running=0
if pgrep -x qadenad > /dev/null 2>&1 || pgrep -x qadenad_enclave > /dev/null 2>&1 \
   || pgrep -f "ego-host" > /dev/null 2>&1; then
    node_running=1
fi

if [[ "$mode" == "install" ]]; then
    echo "  no qadenad and no enclave installed -- FIRST INSTALL"
    if [[ $node_running -eq 1 ]]; then
        fail "something qadena-shaped is running but nothing is installed.  Stop it first:
       scripts/stop_qadena.sh --all"
    fi
else
    cur_version=""; cur_unique=""; cur_signer=""
    if [[ -x "$cur_encl" ]]; then
        cur_unique=$(read_unique "$cur_encl")
        cur_signer=$(read_signer "$cur_encl")
        cur_version=$("$cur_encl" -version 2>&1 | head -1)
    fi
    echo "  a node is already installed -- UPGRADE"
    echo "    enclave installed: ${cur_version:-none}  ${cur_unique:0:16}"
    echo "    enclave in package: $new_version  ${new_unique:0:16}"
    echo "    node running: $([[ $node_running -eq 1 ]] && echo yes || echo no)"

    if [[ -n "$new_unique" && -n "$cur_unique" ]]; then
        # SEALING USES THE PRODUCT KEY, derived from MRSIGNER.  A different signer unseals nothing
        # this node stored, so the upgrade would appear to succeed and leave every wallet,
        # credential and scan-window record unreadable -- with the chain still producing blocks.
        if [[ "$cur_signer" != "$new_signer" ]]; then
            fail "MRSIGNER differs.
       installed: $cur_signer
       package:   $new_signer
       A different signer cannot unseal this node's sealed state.  Refusing."
        fi
        if [[ "$cur_unique" == "$new_unique" ]]; then
            echo "    the same enclave is already installed; no enclave upgrade to perform"
        elif [[ "$cur_version" == "$new_version" ]]; then
            # check_upgrade_enclave.sh triggers on the version being HIGHER, so an equal version
            # installs and then never upgrades -- silently.
            fail "package enclave version $new_version equals the installed one, but the measurement
       differs.  check_upgrade_enclave.sh compares VERSIONS, so this would install and never
       upgrade.  Bump cmd/qadenad_enclave/version.txt and rebuild."
        fi
    fi
fi

# ---------------------------------------------------------------------------------------------
# 3. for an upgrade, wait until the chain will accept the new identity
# ---------------------------------------------------------------------------------------------
identity_status() {
    "$qadenabin/qadenad" --home "$QADENAHOME" query qadena show-enclave-identity "$new_unique" \
        --output json 2>/dev/null | jq -r '.enclaveIdentity.status' 2>/dev/null || true
}

can_activate=1

# A NODE THAT HAS NEVER JOINED A CHAIN HAS NO CHAIN TO ASK.  The staging dance below exists to
# protect a LIVE upgrade: the old enclave hands its sealed keys to the new one only once the chain
# has made the new identity ACTIVE, so switching early loses the handover.  None of that applies to
# a node holding no chain data -- there is no sealed state to hand over and no chain to query, so
# identity_status comes back unreachable, can_activate goes to 0, and the new enclave is staged
# beside the old one FOREVER.  The node then keeps running the measurement it already had.
#
# That is not hypothetical: a joiner installed before an enclave upgrade, then re-installed from the
# upgraded package, reported "installed" while still measuring the OLD id -- and the join was then
# refused for running the wrong build, several steps later and with no hint of why.
node_has_chain_data=0
[[ -e "$QADENAHOME/data/application.db" ]] && node_has_chain_data=1

if [[ "$mode" == "upgrade" && $node_has_chain_data -eq 0 && -n "$new_unique" && "$cur_unique" != "$new_unique" ]]; then
    echo ""
    echo "=== 3. the chain accepts $new_unique ==="
    echo "  SKIPPED: this node holds no chain data, so there is no handover to protect and no chain"
    echo "  to ask.  Installing $new_unique as this node's enclave outright."
elif [[ "$mode" == "upgrade" && -n "$new_unique" && "$cur_unique" != "$new_unique" ]]; then
    echo ""
    echo "=== 3. the chain accepts $new_unique ==="
    if [[ $force -eq 1 ]]; then
        echo "  SKIPPED (--force).  If it is not active, the old enclave will refuse the handover."
    else
        st=$(identity_status)
        echo "  status: ${st:-unreachable}"

        if [[ -z "$st" || "$st" == "null" ]]; then
            echo "  not registered, or the chain is not reachable from here."
            echo "  Register it by governance first:"
            echo "    testscripts/test_update_enclave_identity.sh $new_unique $new_signer unvalidated"
            can_activate=0
        elif [[ "$st" != "active" && $wait_active -eq 1 ]]; then
            # POLL, DO NOT SLEEP-THEN-ASSUME.  Promotion happens on the proposer's enclave at its
            # first UpdateHeight after a restart, so the delay is governed by the chain's schedule
            # and not by anything this machine controls.
            echo "  waiting up to ${wait_secs}s for it to become active..."
            waited=0
            while [[ "$st" != "active" && $waited -lt $wait_secs ]]; do
                sleep 15
                waited=$(( waited + 15 ))
                st=$(identity_status)
                printf "    %4ds  status=%s\n" "$waited" "${st:-unreachable}"
            done
            if [[ "$st" != "active" ]]; then
                fail "the identity was still '${st:-unreachable}' after ${wait_secs}s.
       Nothing has been changed on this node.  Re-run when the chain has promoted it, or raise
       the budget: --wait-active=7200"
            fi
            echo "  ACTIVE"
        elif [[ "$st" != "active" ]]; then
            echo "  not active yet.  The old enclave hands its keys over only to an ACTIVE identity,"
            echo "  so the enclave will be staged but not switched.  Re-run with --wait-active to"
            echo "  have this script wait and then perform the cutover itself."
            can_activate=0
        fi
    fi
fi

# ---------------------------------------------------------------------------------------------
# 4. stop the node if the cutover is actually going to happen
# ---------------------------------------------------------------------------------------------
# WHY STOPPING IS NEEDED AT ALL, AND WHY IT IS NOT ALWAYS NEEDED.
#
#   binaries  ETXTBSY -- Linux refuses to write the image of a running process, and a half-copied
#             binary is worse than none.
#   scripts   subtler, and the reason a scripts-only update still stops the node: a shell reads its
#             script LAZILY, by byte offset.  run.sh is executing the whole time the node is up, so
#             rewriting it underneath the running shell makes it resume at an offset that now lands
#             mid-token.  The failure is arbitrary and looks nothing like an install problem.
#   config    safe -- config.yml, public.pem and node_params.json are read at startup, never held
#             open, so a package containing only those changes nothing that is running.
#
# Deferred to here so that a run which turns out to be blocked -- unregistered identity, wrong
# signer, inactive with no --wait-active -- never takes the node down for nothing.
needs_stop=0
stop_reason=""
stage_only=0
if [[ -n "$(echo "$stage"/bin/*(N))" ]]; then
    needs_stop=1; stop_reason="the packaged binaries are in use (ETXTBSY)"
elif [[ -d "$stage/scripts" ]]; then
    needs_stop=1; stop_reason="run.sh is executing and a shell re-reads its script by byte offset"
fi

if [[ $node_running -eq 1 && $needs_stop -eq 0 ]]; then
    echo ""
    echo "=== 4. the node keeps running ==="
    echo "  this package changes nothing that is currently in use."
elif [[ $node_running -eq 1 ]]; then
    if [[ $can_activate -eq 0 ]]; then
        echo ""
        echo "=== 4. leaving the node running ==="
        echo "  the cutover cannot happen yet, so nothing that is in use will be written."
        echo "  Only the new enclave is staged alongside; the running node is untouched."
        # AND THE INSTALL STEP HAS TO HONOUR THAT.  It used to print this and then install
        # everything anyway, dying on `cp: cannot create regular file .../qadenad: Text file busy`
        # -- a confusing ETXTBSY several screens after a message promising the opposite.  Staging
        # the measurement-named copies is safe on a running node (a new filename is never busy);
        # writing the live names is not, and neither is rewriting scripts/ while run.sh executes
        # out of it by byte offset.
        stage_only=1
    else
        echo ""
        echo "=== 4. stopping the node ==="
        echo "  $stop_reason"
        "$qadenascripts/stop_qadena.sh" --all || fail "could not stop the node"
        sleep 3
        if pgrep -x qadenad > /dev/null 2>&1 || pgrep -f "ego-host" > /dev/null 2>&1; then
            fail "the node is still running after stop_qadena.sh --all; refusing to write over it"
        fi
        node_running=0
        echo "  stopped"
        # A scripts/config-only update has no enclave cutover to perform, so nothing downstream will
        # restart it.  Say so, rather than leaving a validator down and silent.
        if [[ -z "$new_unique" && $restart -eq 0 ]]; then
            echo "  NOTE: this package has no enclave, so nothing below will restart the node."
            echo "        Pass --restart, or start it yourself when the install finishes."
        fi
    fi
fi

# ---------------------------------------------------------------------------------------------
# 5. install
# ---------------------------------------------------------------------------------------------
echo ""
echo "=== 5. install ==="
mkdir -p "$qadenabin" "$QADENAHOME/config" "$QADENAHOME/scripts"

backup_dir="$QADENAHOME/backup/$(date +%Y%m%d-%H%M%S)"
backed_up=0

# Anything that exists and is about to change is copied aside first.  This costs a few hundred MB
# once and is the difference between a bad release being a rollback and being an outage.
preserve() {   # dest
    local dest="$1"
    [[ -f "$dest" ]] || return 0
    local rel="${dest#$QADENAHOME/}"
    mkdir -p "$backup_dir/$(dirname "$rel")"
    cp -p "$dest" "$backup_dir/$rel"
    backed_up=1
}

install_file() {   # src dest
    local src="$1" dest="$2"
    if [[ -f "$dest" ]] && cmp -s "$src" "$dest"; then
        return 0                                  # identical; nothing to preserve, nothing to write
    fi
    preserve "$dest"
    cp "$src" "$dest"
}

# A VERSIONED NAME IS A CLAIM ABOUT CONTENT.  qadenad.1.1.8 or qadenad_enclave.<measurement> already
# existing with DIFFERENT bytes means two different builds are claiming the same identity -- for the
# enclave that is impossible (the name IS the measurement) and for the chain it means an unreproducible
# build got out.  Either way, stop.
install_versioned() {   # src dest label
    local src="$1" dest="$2" label="$3"
    if [[ -f "$dest" ]] && ! cmp -s "$src" "$dest"; then
        fail "$dest already exists with different contents.
       $label in this package is not the same build as the one already installed under that name.
       Refusing to overwrite it; move it aside deliberately if that is really what you want."
    fi
    cp "$src" "$dest"
}

for f in "$stage"/bin/*(N); do
    name=$(basename "$f")
    chmod +x "$f" 2>/dev/null || true
    case "$name" in
        qadenad_enclave)
            # Staged under its measurement, ALWAYS.  Both binaries have to be on disk for the
            # handover: the old enclave boots in --upgrade-mode and passes its sealed keys to the new
            # one.  Deleting the old one is what makes an upgrade unrecoverable.
            install_versioned "$f" "$qadenabin/qadenad_enclave.$new_unique" "qadenad_enclave"
            echo "  staged   qadenad_enclave.$new_unique"
            ;;
        signer_enclave)
            m=$(read_unique "$f")
            install_versioned "$f" "$qadenabin/signer_enclave.$m" "signer_enclave"
            if [[ $stage_only -eq 1 ]]; then
                echo "  staged   signer_enclave.$m (live copy left alone -- node is running)"
            else
                install_file "$f" "$qadenabin/signer_enclave"
                echo "  installed signer_enclave ($m)"
            fi
            ;;
        qadenad)
            # cobra wants the `version` SUBCOMMAND, not -version, and qadenad links libwasmvm at load
            # time -- so the staged libs have to be on the path for it to answer at all.
            v=$(LD_LIBRARY_PATH="$stage/bin:$qadenabin" "$f" version 2>/dev/null | head -1)
            [[ -n "$v" ]] || v="$(mval qadenad.version)"
            [[ -n "$v" ]] || v="unknown"
            install_versioned "$f" "$qadenabin/qadenad.$v" "qadenad"
            if [[ $stage_only -eq 1 ]]; then
                echo "  staged   qadenad.$v (live copy left alone -- node is running)"
            else
                install_file "$f" "$qadenabin/qadenad"
                echo "  installed qadenad ($v)"
            fi
            ;;
        libwasmvm*.so)
            # Loaded at process start and held open for the life of the node, so replacing it under
            # a running qadenad is the same hazard as the binary itself.
            if [[ $stage_only -eq 1 ]]; then
                echo "  skipped  $name (node is running)"
            else
                install_file "$f" "$qadenabin/$name"
                echo "  installed $name"
            fi
            ;;
        cosmovisor)
            # A REAL FILE, always -- cosmovisor can never live inside (or be a symlink into) the
            # tree it swaps.  Not versioned under a measurement (it is not one of the node's
            # attested artifacts); the manifest's cosmovisor.version records what shipped.  While
            # the node runs, cosmovisor IS the running supervisor, so it gets the same
            # stage-only deference as every other live binary.
            if [[ $stage_only -eq 1 ]]; then
                echo "  skipped  cosmovisor (node is running; it will install on the next stopped install)"
            else
                install_file "$f" "$qadenabin/cosmovisor"
                chmod +x "$qadenabin/cosmovisor"
                echo "  installed cosmovisor ($(mval cosmovisor.version))"
            fi
            ;;
    esac
done

# prune_dir <dir> -- delete installed files the package no longer ships.
#
# WITHOUT THIS, "installed" and "the current release" drift apart permanently.  Copying only ever
# adds and overwrites, so a script deleted upstream lives on every node forever -- and dead scripts
# are worse than missing ones, because they still run when someone types their name.  Observed with
# install_enclave_upgrade.sh, which was superseded and removed but stayed on the node that had it.
#
# NEVER FOR A DELTA PACKAGE.  --changed-since ships only the components whose checksum moved, so
# "not in this package" means "unchanged", not "withdrawn".  Pruning against one would delete
# almost everything.  The manifest records update.since exactly when that applies, so that is the
# guard.  It is checked once, up front, rather than per directory.
prune_dir() {
    local d="$1" src="$stage/$1" dst="$QADENAHOME/$1"
    [[ -d "$src" && -d "$dst" ]] || return 0
    local pruned=0 f name
    for f in "$dst"/*(N); do
        [[ -f "$f" ]] || continue
        name="${f:t}"
        [[ -e "$src/$name" ]] && continue
        preserve "$f"          # recoverable from $QADENAHOME/backup/<timestamp>/
        rm -f "$f"
        echo "    pruned $d/$name"
        pruned=$(( pruned + 1 ))
    done
    [[ $pruned -eq 0 ]] || echo "  pruned $pruned stale file(s) from $d (backed up)"
}

is_delta=0
if grep -q '^update.since:' "$stage/manifest.txt" 2>/dev/null; then
    is_delta=1
fi

if [[ -d "$stage/scripts" && $stage_only -eq 1 ]]; then
    echo "  skipped  scripts/ (node is running; run.sh re-reads its own script by byte offset)"
elif [[ -d "$stage/scripts" ]]; then
    changed=0
    for f in "$stage"/scripts/*(N); do
        dest="$QADENAHOME/scripts/$(basename "$f")"
        if [[ ! -f "$dest" ]] || ! cmp -s "$f" "$dest"; then changed=$(( changed + 1 )); fi
        install_file "$f" "$dest"
        chmod +x "$dest" 2>/dev/null || true
    done
    echo "  installed scripts ($changed changed)"
    if [[ $prune -eq 1 && $is_delta -eq 0 ]]; then
        prune_dir scripts
    fi
fi

for d in testscripts test_data; do
    [[ -d "$stage/$d" ]] || continue
    mkdir -p "$QADENAHOME/$d"
    for f in "$stage"/$d/*(N); do
        install_file "$f" "$QADENAHOME/$d/$(basename "$f")"
        [[ "$d" == testscripts ]] && chmod +x "$QADENAHOME/$d/$(basename "$f")" 2>/dev/null || true
    done
    echo "  installed $d"
    if [[ $prune -eq 1 && $is_delta -eq 0 ]]; then
        prune_dir "$d"
    fi
done

if [[ $is_delta -eq 1 && $prune -eq 1 ]]; then
    echo "  (pruning skipped: this is an update package, so absence means unchanged)"
fi

if [[ -f "$stage/config/public.pem" ]]; then
    dest="$QADENAHOME/config/public.pem"
    # ONLY AN EGO-SIGNED PACKAGE HAS A SIGNER TO COMPARE.  A debug package carries public.pem because
    # install.sh ships it and it costs 621 bytes, but no key signed that enclave, so `ego signerid`
    # has nothing to say and the comparison below would be between two empty strings -- a check that
    # can never fail, which is worse than one that is skipped and admits it.
    pem_signer=""
    if [[ "$identity_mode" == "sgx" ]]; then
        pem_signer=$(ego signerid "$stage/config/public.pem" 2>/dev/null | tail -1)
        if [[ -f "$dest" ]]; then
            old_signer=$(ego signerid "$dest" 2>/dev/null | tail -1)
            # public.pem records which enclave signer this node was set up for.  A package carrying a
            # different one is the MRSIGNER change in file form, so refuse it here too.
            #
            # Today this is belt-and-braces rather than load-bearing: keeper.InitEnclave checks
            # SupportsUnixDomainSockets first, that is hardcoded true, and the socket path only LOGS
            # the signer id -- the attested dial that would verify it is unreachable.  The MRSIGNER
            # check in section 2 is the one that actually protects sealed state.  This check costs
            # nothing and starts mattering the moment the socket path is not the only one.
            if [[ -n "$old_signer" && "$old_signer" != "$pem_signer" ]]; then
                fail "public.pem here signs as $old_signer, the package's as $pem_signer.
       This node was set up for $old_signer.  Refusing to replace it."
            fi
        fi
    fi
    install_file "$stage/config/public.pem" "$dest"
    echo "  installed config/public.pem${pem_signer:+ (signer $pem_signer)}"
fi

if [[ -f "$stage/config/node_params.json" ]]; then
    dest="$QADENAHOME/config/node_params.json"
    if [[ -f "$dest" ]]; then
        # ONCE SUBSTITUTED IT IS NODE IDENTITY.  The shipped copy still says "PioneerID"; the one
        # here says which pioneer this node is.  Writing the template over it would rename the node
        # to a placeholder, so an existing file is always left alone.
        echo "  config/node_params.json exists (pioneer_id kept as-is)"
    else
        cp "$stage/config/node_params.json" "$dest"
        echo "  installed config/node_params.json (template)"
    fi
fi

if [[ -f "$stage/config/config.yml" ]]; then
    dest="$QADENAHOME/config/config.yml"
    if [[ ! -f "$dest" ]]; then
        cp "$stage/config/config.yml" "$dest"
        echo "  installed config/config.yml"
    elif cmp -s "$stage/config/config.yml" "$dest"; then
        echo "  config/config.yml unchanged"
    else
        # OPERATOR-OWNED.  It carries minimum-gas-prices and per-deployment settings that whoever
        # runs this node may have tuned, and the packager has no way to know.  Put the new one
        # beside it and say so; do not decide on their behalf.
        cp "$stage/config/config.yml" "$dest.new"
        echo "  config/config.yml DIFFERS -- kept yours, wrote the package's as config.yml.new"
        echo "                              diff $dest $dest.new"
    fi
fi

if [[ $backed_up -eq 1 ]]; then
    echo "  replaced files backed up in $backup_dir"
fi

# ---------------------------------------------------------------------------------------------
# 6. make the new enclave current
# ---------------------------------------------------------------------------------------------
if [[ -n "$new_unique" ]]; then
    echo ""
    echo "=== 6. enclave ==="
    if [[ "$mode" == "install" ]]; then
        cp "$new_encl" "$qadenabin/qadenad_enclave"
        echo "  installed as this node's enclave"
    elif [[ "$cur_unique" == "$new_unique" ]]; then
        echo "  already current; nothing to switch"
    elif [[ $can_activate -eq 1 ]]; then
        cp "$new_encl" "$qadenabin/qadenad_enclave"
        echo "  ACTIVATED.  The next start performs the handover: the old enclave boots in"
        echo "  --upgrade-mode and passes its sealed keys to the new one.  Both binaries stay on"
        echo "  disk, which is what makes that possible -- do not delete the old one."
    else
        echo "  STAGED but not activated; this node still runs $cur_version (${cur_unique:0:16})."
        echo "  When the chain has promoted $new_unique, finish with:"
        # Re-invoke however this run was invoked -- from the unpacked package on a target machine,
        # or from a checkout against the archive.
        if [[ -n "$archive" ]]; then
            echo "    $0 $archive --wait-active --restart"
        else
            echo "    $0 --wait-active --restart"
        fi
    fi
fi

# ---------------------------------------------------------------------------------------------
# 6b. say so if this ran under sudo
# ---------------------------------------------------------------------------------------------
# Only reached via the workaround (see the header); root is not required to install.  Everything
# just written is root-owned, so the operator's own `qadenad q ...` cannot read its 0600
# config/client.toml and fails before it opens a socket -- that is not hypothetical, it stopped
# add_full_node.sh's enclave pre-check on a freshly installed node and the refusal blamed the seed.
#
# SAY IT, DO NOT FIX IT.  `chown -R` here would be wrong on the case this path exists for: a machine
# whose operator cannot open /dev/sgx_* runs the node as root, and its home holds priv_validator_key
# .json (0600), data/ and keyring-* (0700) and the enclave's sealed params.  Recursively handing
# those to the login account on an UPGRADE is a privilege change no one asked for.  Whether the node
# is meant to run as root is a question this script cannot answer, so it names the fix and leaves it.
if [[ -n "$SUDO_USER" ]] && [[ -d "$QADENAHOME" ]]; then
    echo ""
    echo "  NOTE: sudo was not required to install -- it writes only into $QADENAHOME."
    echo "        Everything installed is now owned by root, so $SUDO_USER's CLI will fail with"
    echo "        \"couldn't get client config\" until that is corrected.  If this node is NOT"
    echo "        meant to run as root:"
    echo "            sudo chown -R $SUDO_USER $QADENAHOME"
fi

# ---------------------------------------------------------------------------------------------
# 7. start
# ---------------------------------------------------------------------------------------------
echo ""
if [[ "$mode" == "install" ]]; then
    echo "=== installed.  This node has binaries but has not joined a chain. ==="
    echo "  join an existing chain:  scripts/add_full_node.sh"
    echo "  then, to validate:       scripts/convert_to_validator.sh --validator-stake <amount>"
    echo ""
    echo "  This enclave must be registered and active on that chain before the node can take part:"
    echo "    $new_unique"
elif [[ $restart -eq 1 && $can_activate -eq 1 ]]; then
    echo "=== starting ==="
    "$qadenascripts/start_qadena.sh"
else
    echo "=== done ==="
    # An `if`, not `[[ ... ]] && echo`: as the last command under set -e, a false test would make a
    # successful install exit non-zero.
    if [[ $can_activate -eq 1 ]]; then
        echo "  start with: scripts/start_qadena.sh"
    fi
fi
