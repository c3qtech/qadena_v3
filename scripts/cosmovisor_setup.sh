#!/bin/zsh
# Convert this node to cosmovisor management, or verify a conversion that already happened.
#
#   cosmovisor_setup.sh            convert (node must be stopped)
#   cosmovisor_setup.sh --check    report the layout without changing anything
#
# WHAT "CONVERTED" MEANS, precisely:
#
#   $QADENAHOME/cosmovisor/genesis/bin/     the four artifacts, as REAL FILES:
#                                           qadenad, qadenad_enclave, signer_enclave, libwasmvm*.so
#   $QADENAHOME/cosmovisor/current          symlink -> genesis (cosmovisor repoints it per upgrade)
#   $QADENAHOME/cosmovisor/<preupgrade>     the at-height hook (a shim; see cosmovisor_preupgrade.sh)
#   $QADENAHOME/bin/<those five names>      SYMLINKS into cosmovisor/current/bin/
#
# The symlinks are the contract that keeps the other ~95 scripts working: every consumer reaches
# binaries through $qadenabin, and setup_env.sh prepends $qadenabin to LD_LIBRARY_PATH -- which
# BEATS the binary's $ORIGIN rpath, so if the .so names were left as real files a post-upgrade
# qadenad would load the pre-upgrade libwasmvm.  Symlinked, every path follows the swap.
#
# What stays REAL in $QADENAHOME/bin: cosmovisor itself (it can never live inside the tree it
# swaps), and every versioned copy (qadenad.<ver>, qadenad_enclave.<measurement>, ...) -- the
# attested enclave handoff and install_release's identity checks read those.
#
# RE-RUNNABLE, and needs to be: buildscripts/init.sh and reset_qadena_fast.sh `rm -rf $QADENAHOME`,
# which silently DE-CONVERTS a node (and deletes cosmovisor itself).  Any bringup that wipes must
# call this again after its install step.
#
# SGX NOTE: nothing here starts an enclave, so no devices and no root are needed.  Files are moved
# with `mv` (ownership preserved); a fleet whose node runs via device-group membership converts
# identically to one using sudo.

# NO `set -e`: setup_env.sh runs a chain query while being sourced (set_min_gas_price), which
# fails on a STOPPED node -- and this script's whole precondition is a stopped node.  Errors on
# the steps that matter are checked explicitly instead.
SCRIPT_DIR="${0:A:h}"
source "$SCRIPT_DIR/setup_env.sh"

CHECK=0
# not `[[ ]] && CHECK=1`: under set -e a false test at top level is a fatal "error"
if [[ "${1:-}" == "--check" ]]; then CHECK=1; fi

CV_TREE="$QADENAHOME/cosmovisor"
GEN_BIN="$CV_TREE/genesis/bin"
NAMES=(qadenad qadenad_enclave signer_enclave)

say()  { echo "cosmovisor_setup.sh: $*" }
die()  { echo "cosmovisor_setup.sh: $*" >&2; exit 1 }

# ---------------------------------------------------------------------------------------------
if (( CHECK )); then
    if [[ ! -L "$CV_TREE/current" ]]; then
        say "NOT MANAGED: no $CV_TREE/current symlink"
        exit 1
    fi
    say "current -> $(readlink "$CV_TREE/current")"
    rc=0
    for n in $NAMES libwasmvm.aarch64.so libwasmvm.x86_64.so; do
        if [[ -L "$qadenabin/$n" ]]; then
            tgt=$(readlink "$qadenabin/$n")
            [[ -e "$qadenabin/$n" ]] || { say "  BROKEN symlink: $n -> $tgt"; rc=1; continue }
            say "  ok: $n -> $tgt"
        elif [[ -e "$qadenabin/$n" ]]; then
            say "  REAL FILE (should be a symlink): $qadenabin/$n"; rc=1
        else
            say "  missing: $qadenabin/$n"
            # the .so for the other arch legitimately doesn't exist; only the three binaries are fatal
            if [[ " ${NAMES[*]} " == *" $n "* ]]; then rc=1; fi
        fi
    done
    [[ -x "$qadenabin/cosmovisor" ]] && say "  ok: cosmovisor ($($qadenabin/cosmovisor version 2>&1 | grep -oE 'v[0-9.]+' | head -1))" \
                                     || { say "  missing: $qadenabin/cosmovisor"; rc=1 }
    exit $rc
fi

# ---------------------------------------------------------------------------------------------
# Conversion.  Refuse under a running node: mv of a live binary technically works (the inode
# survives), but every downstream check would then describe a node whose disk no longer matches
# its processes, and there is no reason to reason about that state.
if is_qadena_running; then
    die "the node is running -- stop_qadena.sh --all first.  Converting under a live node leaves \
processes running from paths that no longer exist."
fi

[[ -x "$qadenabin/cosmovisor" ]] || die "no cosmovisor at $qadenabin/cosmovisor -- \
buildscripts/build_cosmovisor.sh (build host) or install a package that carries it."

if [[ -L "$CV_TREE/current" ]]; then
    say "already managed (current -> $(readlink "$CV_TREE/current")); verifying instead"
    exec "$0" --check
fi

for n in $NAMES; do
    [[ -f "$qadenabin/$n" ]] || die "no $qadenabin/$n to convert -- install binaries first (install.sh / install_release.sh)"
    if [[ -L "$qadenabin/$n" ]]; then die "$qadenabin/$n is already a symlink but there is no current link -- half-converted tree; fix by hand"; fi
done

say "creating $GEN_BIN"
mkdir -p "$GEN_BIN" || die "cannot create $GEN_BIN"

# cosmovisor init would copy qadenad and create `current`, but it knows nothing of the enclaves or
# the libs, and we want ONE move semantics for all five -- so the layout is built directly, matching
# what `cosmovisor init` produces (verified against the pinned source: genesis/bin + a RELATIVE
# `current` symlink, created from inside the cosmovisor dir).
for n in $NAMES; do
    mv "$qadenabin/$n" "$GEN_BIN/$n" || die "mv $n failed -- tree is part-converted; move files back from $GEN_BIN by hand"
done
for so in "$qadenabin"/libwasmvm*.so(N); do
    b=$(basename "$so")
    mv "$so" "$GEN_BIN/$b" || die "mv $b failed -- tree is part-converted; move files back from $GEN_BIN by hand"
done

( cd "$CV_TREE" && ln -s genesis current ) || die "cannot create the current symlink"

say "symlinking $qadenabin names into cosmovisor/current/bin"
for f in "$GEN_BIN"/*(N); do
    b=$(basename "$f")
    ln -s "../cosmovisor/current/bin/$b" "$qadenabin/$b" || die "cannot symlink $b"
done

# ---------------------------------------------------------------------------------------------
# Sanity: the links resolve, and the dynamic loader finds libwasmvm through them.
for n in $NAMES; do
    [[ -e "$qadenabin/$n" ]] || die "post-conversion check failed: $qadenabin/$n does not resolve"
done
if ! LD_LIBRARY_PATH="$qadenabin" "$qadenabin/qadenad" version >/dev/null 2>&1; then
    die "post-conversion check failed: qadenad does not start through the symlink (libwasmvm resolution?)"
fi

say "converted.  current -> $(readlink "$CV_TREE/current")"
say "run.sh will now launch through cosmovisor; stop_qadena.sh / start_qadena.sh are unchanged."
