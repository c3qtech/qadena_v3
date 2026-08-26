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

set -e
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

echo "build_cosmovisor.sh: building cosmovisor $PIN"
tmp=$(mktemp -d)
trap "rm -rf $tmp" EXIT
GOBIN="$tmp" go install "cosmossdk.io/tools/cosmovisor/cmd/cosmovisor@$PIN"

mkdir -p "$qadenabin"
# cp to a temp name + mv: never rewrite a possibly-running supervisor's inode in place -- the
# same-inode overwrite lesson from libwasmvm (install.sh) applies to any live binary.
cp "$tmp/cosmovisor" "$qadenabin/cosmovisor.new.$$"
mv -f "$qadenabin/cosmovisor.new.$$" "$qadenabin/cosmovisor"
echo "build_cosmovisor.sh: installed $($qadenabin/cosmovisor version 2>&1 | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1) at $qadenabin/cosmovisor"
