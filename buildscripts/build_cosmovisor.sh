#!/bin/zsh
# Build the pinned cosmovisor into $qadenabin/cosmovisor.
#
# WHY A PIN AND A BUILD, not `go install @latest`: cosmovisor's behavior at the upgrade height IS
# the deploy mechanism -- the custom-preupgrade hook's location ($DAEMON_HOME/cosmovisor/<name>),
# its argv (<plan-name> <height>), and its ordering (after backup, BEFORE the current-symlink
# flip; a non-zero exit aborts the swap) were all verified against the pinned tag's source, and a
# silently newer cosmovisor could move any of them.  The pin lives in cosmovisor_version.txt
# beside this script; bumping it means re-verifying those three facts against the new tag
# (tools/cosmovisor: process.go doCustomPreUpgrade, cmd/cosmovisor/init.go).
#
# WHY IT LANDS IN $qadenabin AS A REAL FILE: cosmovisor cannot live inside the tree it swaps, and
# package_release.sh ships $qadenabin/cosmovisor to the fleet (all aarch64, same as the build
# host) so joiners need no Go toolchain.  The Mac builds its own with this same script.
#
# `go install pkg@version` intentionally runs OUTSIDE the repo module: the repo builds with
# -mod=vendor and cosmovisor is not vendored; module-aware install with an explicit version
# ignores the surrounding module, which is exactly what we want.

# NO `set -e`: setup_env.sh runs a chain query while being sourced (set_min_gas_price), which
# fails on a STOPPED node -- and this script's whole precondition is a stopped node.  Errors on
# the steps that matter are checked explicitly instead.
SCRIPT_DIR="${0:A:h}"

# READ THE PIN BEFORE SOURCING setup_env.sh -- it redefines SCRIPT_DIR to scripts/, and the pin
# lives beside THIS script in buildscripts/.  Cost one silent "no such file" to learn.
PIN=$(tr -d '[:space:]' < "$SCRIPT_DIR/cosmovisor_version.txt")
[[ -n "$PIN" ]] || { echo "build_cosmovisor.sh: cosmovisor_version.txt is empty" >&2; exit 1 }

source "$SCRIPT_DIR/../scripts/setup_env.sh"

command -v go >/dev/null || { echo "build_cosmovisor.sh: no go toolchain on PATH" >&2; exit 1 }

# Already the pinned version?  `cosmovisor version` prints "cosmovisor version: <v>" to stderr in
# some releases and stdout in others -- capture both and match loosely on the tag.
if [[ -x "$qadenabin/cosmovisor" ]]; then
    have=$("$qadenabin/cosmovisor" version 2>&1 | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    if [[ "$have" == "$PIN" ]]; then
        echo "build_cosmovisor.sh: $qadenabin/cosmovisor is already $PIN"
        exit 0
    fi
    echo "build_cosmovisor.sh: replacing cosmovisor $have with $PIN"
fi

# THE CACHE LIVES OUTSIDE $QADENAHOME, and that is the whole point of it.
#
# $qadenabin is $QADENAHOME/bin, and `stop_fleet.sh --purge` does `rm -rf $HOME/qadena` -- so every
# purge deletes cosmovisor and the already-$PIN check above can never fire on the next bringup.
# That is why this appeared to fetch from the network on every single run: not because the pin was
# moving, but because the artifact kept being thrown away with the chain data.
#
# Keyed BY PIN, so bumping cosmovisor_version.txt cannot silently reuse the old binary -- the
# whole reason for the pin is that a different cosmovisor changes the deploy mechanism.
CACHE_DIR="${QADENA_COSMOVISOR_CACHE:-$HOME/.cache/qadena}"
CACHED="$CACHE_DIR/cosmovisor-$PIN-$(uname -s)-$(uname -m)"

# uname in the name because this cache is per-ARCHITECTURE.  The Mac builds darwin/arm64 for
# itself and the fleet builds linux/aarch64 for the nodes; one path for both would hand a node a
# Mach-O binary and the failure ("cannot execute binary file") names neither the cache nor this
# script.

mkdir -p "$qadenabin"
if [[ -x "$CACHED" ]]; then
    cached_v=$("$CACHED" version 2>&1 | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    if [[ "$cached_v" == "$PIN" ]]; then
        echo "build_cosmovisor.sh: reusing cached $PIN from $CACHED (no build, no network)"
        cp "$CACHED" "$qadenabin/cosmovisor.new.$$"
        mv -f "$qadenabin/cosmovisor.new.$$" "$qadenabin/cosmovisor"
        echo "build_cosmovisor.sh: installed $PIN at $qadenabin/cosmovisor"
        exit 0
    fi
    # A cached file that does not report the pin is not the pin.  Rebuild rather than trust the
    # filename: the name is a label, the `version` output is evidence.
    echo "build_cosmovisor.sh: cached binary reports '${cached_v:-nothing}', not $PIN -- rebuilding"
fi

echo "build_cosmovisor.sh: building cosmovisor $PIN"
tmp=$(mktemp -d)
trap "rm -rf $tmp" EXIT
GOBIN="$tmp" go install "cosmossdk.io/tools/cosmovisor/cmd/cosmovisor@$PIN"
# cp to a temp name + mv: never rewrite a possibly-running supervisor's inode in place -- the
# same-inode overwrite lesson from libwasmvm (install.sh) applies to any live binary.
cp "$tmp/cosmovisor" "$qadenabin/cosmovisor.new.$$"
mv -f "$qadenabin/cosmovisor.new.$$" "$qadenabin/cosmovisor"
echo "build_cosmovisor.sh: installed $($qadenabin/cosmovisor version 2>&1 | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1) at $qadenabin/cosmovisor"

# SEED THE CACHE, best-effort.  A failure here must not fail the build: the binary is already
# installed and correct, and the cache is only an optimisation for the next purge.
if mkdir -p "$CACHE_DIR" 2>/dev/null; then
    if cp "$tmp/cosmovisor" "$CACHED.new.$$" 2>/dev/null && mv -f "$CACHED.new.$$" "$CACHED" 2>/dev/null; then
        echo "build_cosmovisor.sh: cached at $CACHED -- a --purge will not force a rebuild"
    else
        rm -f "$CACHED.new.$$" 2>/dev/null
        echo "build_cosmovisor.sh: could not write $CACHED (continuing; the binary is installed)"
    fi
fi
