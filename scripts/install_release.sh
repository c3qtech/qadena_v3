#!/bin/zsh
#
# Install or upgrade a Qadena node from a package built by buildscripts/package_release.sh.
#
#   scripts/install_release.sh <archive.tar.gz> [--wait-active[=SECONDS]] [--restart] [--force]
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

SCRIPT_DIR="${0:A:h}"
source "$SCRIPT_DIR/../scripts/setup_env.sh"

set -e

archive=""
wait_active=0
wait_secs=1800
restart=0
force=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --wait-active)    wait_active=1; shift ;;
    --wait-active=*)  wait_active=1; wait_secs="${1#*=}"; shift ;;
    --restart)        restart=1; shift ;;
    --force)          force=1; shift ;;
    --help)
      sed -n '2,41p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) archive="$1"; shift ;;
  esac
done

fail() { echo ""; echo "install_release.sh: $1" >&2; exit 1; }
mval() { grep "^$1:" "$stage/manifest.txt" 2>/dev/null | awk '{print $2}'; }

[[ -n "$archive" ]] || fail "no archive given.  Usage: install_release.sh <archive.tar.gz>"
[[ -f "$archive" ]] || fail "no such archive: $archive"
archive="${archive:A}"

stage=$(mktemp -d) || fail "could not create a staging directory"
trap 'rm -rf "$stage"' EXIT INT TERM
tar -xzf "$archive" -C "$stage" || fail "could not extract $archive"
[[ -f "$stage/manifest.txt" ]] || fail "$archive has no manifest -- is it a qadena release package?"

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
        scripts/*|testscripts/*|test_data/*) ;;
        config/config.yml|config/public.pem) ;;
        *) fail "the package contains '$entry', which this installer will not write.
       Only binaries, scripts, testscripts, config.yml and public.pem are installable.  Node
       identity and chain state are never distributed." ;;
    esac
done < "$stage/sha256sums.txt"
echo "  every path is installable"

new_encl="$stage/bin/qadenad_enclave"
new_unique=""; new_signer=""; new_version=""
if [[ -f "$new_encl" ]]; then
    chmod +x "$new_encl"
    command -v ego > /dev/null 2>&1 || fail "ego is not installed; cannot verify the enclave"
    new_unique=$(ego uniqueid "$new_encl" 2>/dev/null | tail -1)
    new_signer=$(ego signerid "$new_encl" 2>/dev/null | tail -1)
    new_version=$("$new_encl" -version 2>&1 | head -1)
    # The checksum proves the bytes arrived intact; the MEASUREMENT is what the chain actually
    # accepts, so verify the binary measures what the manifest promised.
    [[ "$new_unique" == "$(mval qadenad_enclave.unique_id)" ]] \
        || fail "qadenad_enclave measures $new_unique but the manifest says $(mval qadenad_enclave.unique_id)"
    echo "  qadenad_enclave measures $new_unique"
fi
if [[ -f "$stage/bin/signer_enclave" ]]; then
    chmod +x "$stage/bin/signer_enclave"
    s=$(ego uniqueid "$stage/bin/signer_enclave" 2>/dev/null | tail -1)
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
        cur_unique=$(ego uniqueid "$cur_encl" 2>/dev/null | tail -1)
        cur_signer=$(ego signerid "$cur_encl" 2>/dev/null | tail -1)
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
if [[ "$mode" == "upgrade" && -n "$new_unique" && "$cur_unique" != "$new_unique" ]]; then
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
# ETXTBSY: Linux refuses to write the image of a running process, and a half-copied binary is worse
# than none.  Stopping is deferred to here so that a run which turns out to be blocked -- unregistered
# identity, wrong signer, inactive with no --wait-active -- never takes the node down for nothing.
if [[ $node_running -eq 1 ]]; then
    if [[ $can_activate -eq 0 ]]; then
        echo ""
        echo "=== 4. leaving the node running ==="
        echo "  the cutover cannot happen yet, so nothing that is in use will be written."
        echo "  Only the new enclave is staged alongside; the running node is untouched."
    else
        echo ""
        echo "=== 4. stopping the node for the cutover ==="
        "$qadenascripts/stop_qadena.sh" --all || fail "could not stop the node"
        sleep 3
        if pgrep -x qadenad > /dev/null 2>&1 || pgrep -f "ego-host" > /dev/null 2>&1; then
            fail "the node is still running after stop_qadena.sh --all; refusing to write over it"
        fi
        node_running=0
        echo "  stopped"
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
            m=$(ego uniqueid "$f" 2>/dev/null | tail -1)
            install_versioned "$f" "$qadenabin/signer_enclave.$m" "signer_enclave"
            install_file "$f" "$qadenabin/signer_enclave"
            echo "  installed signer_enclave ($m)"
            ;;
        qadenad)
            # cobra wants the `version` SUBCOMMAND, not -version, and qadenad links libwasmvm at load
            # time -- so the staged libs have to be on the path for it to answer at all.
            v=$(LD_LIBRARY_PATH="$stage/bin:$qadenabin" "$f" version 2>/dev/null | head -1)
            [[ -n "$v" ]] || v="$(mval qadenad.version)"
            [[ -n "$v" ]] || v="unknown"
            install_versioned "$f" "$qadenabin/qadenad.$v" "qadenad"
            install_file "$f" "$qadenabin/qadenad"
            echo "  installed qadenad ($v)"
            ;;
        libwasmvm*.so)
            install_file "$f" "$qadenabin/$name"
            echo "  installed $name"
            ;;
    esac
done

if [[ -d "$stage/scripts" ]]; then
    changed=0
    for f in "$stage"/scripts/*(N); do
        dest="$QADENAHOME/scripts/$(basename "$f")"
        if [[ ! -f "$dest" ]] || ! cmp -s "$f" "$dest"; then changed=$(( changed + 1 )); fi
        install_file "$f" "$dest"
        chmod +x "$dest" 2>/dev/null || true
    done
    echo "  installed scripts ($changed changed)"
fi

for d in testscripts test_data; do
    [[ -d "$stage/$d" ]] || continue
    mkdir -p "$QADENAHOME/$d"
    for f in "$stage"/$d/*(N); do
        install_file "$f" "$QADENAHOME/$d/$(basename "$f")"
        [[ "$d" == testscripts ]] && chmod +x "$QADENAHOME/$d/$(basename "$f")" 2>/dev/null || true
    done
    echo "  installed $d"
done

if [[ -f "$stage/config/public.pem" ]]; then
    dest="$QADENAHOME/config/public.pem"
    pem_signer=$(ego signerid "$stage/config/public.pem" 2>/dev/null | tail -1)
    if [[ -f "$dest" ]]; then
        old_signer=$(ego signerid "$dest" 2>/dev/null | tail -1)
        # public.pem IS the node's answer to "which enclave signer do I trust".  Replacing it with a
        # different one is the MRSIGNER change again, in file form -- so refuse it here too rather
        # than let the node start and be rejected by the chain for a reason nobody will connect back
        # to this install.
        if [[ -n "$old_signer" && "$old_signer" != "$pem_signer" ]]; then
            fail "public.pem here signs as $old_signer, the package's as $pem_signer.
       This node's sealed state belongs to $old_signer.  Refusing to replace it."
        fi
    fi
    install_file "$stage/config/public.pem" "$dest"
    echo "  installed config/public.pem (signer $pem_signer)"
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
        echo "    scripts/install_release.sh $archive --wait-active --restart"
    fi
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
