#!/bin/zsh
#
# Package a built enclave for distribution to other nodes.
#
# WHY DISTRIBUTE RATHER THAN REBUILD.  The SGX build is reproducible -- the same commit produces the
# same MRENCLAVE on every machine, which this repo verifies in the sgx-build suite and which has held
# across separate hosts.  That is exactly what makes copying the signed binary EQUIVALENT to
# rebuilding it, and it turns a ~24 minute reproducible docker build on every node into a few
# seconds.  A fleet builds once, distributes the artifact, and each operator verifies on arrival that
# what they received measures what governance approved.
#
# The archive deliberately contains ONLY the binaries and a manifest.  Sealed state is per-node --
# enclave_params_<id>.json is sealed to that machine's enclave, and each node's OLD enclave hands its
# keys to its own NEW one during the upgrade.  Copying sealed state between nodes would at best fail
# to unseal and at worst move keys somewhere they were never meant to be.
#
#   ./buildscripts/package_enclave_upgrade.sh [--out <dir>] [--with-chain]
#
# Run it AFTER buildscripts/build_enclave.sh --build-sgx (or init.sh --build-sgx).

SCRIPT_DIR="${0:A:h}"
source "$SCRIPT_DIR/../scripts/setup_env.sh"

set -e

outdir="."
with_chain=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out)
      [[ -n "$2" && "$2" != --* ]] || { echo "Error: --out requires a directory"; exit 1; }
      outdir="$2"; shift 2 ;;
    --with-chain) with_chain=1; shift ;;
    --help)
      echo "Usage: package_enclave_upgrade.sh [--out <dir>] [--with-chain]"
      echo ""
      echo "Packages the signed enclave (and optionally qadenad) for installation on other nodes."
      echo "Run after build_enclave.sh --build-sgx."
      exit 0 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

fail() { echo "package_enclave_upgrade.sh: $1" >&2; exit 1; }

enclave_src="$qadenabuild/cmd/qadenad_enclave/qadenad_enclave"
chain_src="$qadenabuild/cmd/qadenad/qadenad"

[[ -x "$enclave_src" ]] || fail "no built enclave at $enclave_src -- run build_enclave.sh --build-sgx first"

# SIGNED, not merely built.  A debug binary would install cleanly and then be refused by the chain,
# which is a confusing way to discover the build flag was missing.
command -v ego > /dev/null 2>&1 || fail "ego is not installed; this packages an SGX enclave"
unique_id=$(ego uniqueid "$enclave_src" 2>/dev/null | tail -1) \
    || fail "$enclave_src is not an ego-signed enclave -- was it built with --build-sgx?"
signer_id=$(ego signerid "$enclave_src" 2>/dev/null | tail -1)
[[ "$unique_id" =~ ^[0-9a-f]{64}$ ]] \
    || fail "$enclave_src is not ego-signed (no measurement); rebuild with --build-sgx"

version=$("$enclave_src" -version 2>&1 | head -1)
commit=$(cd "$qadenabuild" && git rev-parse --short HEAD 2>/dev/null || echo unknown)
dirty=$(cd "$qadenabuild" && [ -n "$(git status --porcelain)" ] && echo yes || echo no)

# A dirty tree means the artifact does not correspond to any commit, so nobody else can reproduce
# the measurement -- which is the entire basis for trusting a distributed binary.
[[ "$dirty" == "no" ]] || fail "the working tree is dirty; the measurement would correspond to no commit and could not be reproduced by anyone else"

mkdir -p "$outdir"
stage=$(mktemp -d) || fail "could not create a staging directory"
trap 'rm -rf "$stage"' EXIT INT TERM

cp "$enclave_src" "$stage/qadenad_enclave"
included="qadenad_enclave"
if [[ $with_chain -eq 1 ]]; then
    [[ -x "$chain_src" ]] || fail "--with-chain but no built chain at $chain_src"
    cp "$chain_src" "$stage/qadenad"
    included="$included qadenad"
fi

# The manifest is what the installer checks against.  It carries the measurement so a corrupted or
# substituted binary is caught before installation, and the SIGNER so the installer can refuse an
# enclave that could not unseal the existing state.
cat > "$stage/manifest.txt" <<EOF
qadena enclave upgrade package
version:    $version
unique_id:  $unique_id
signer_id:  $signer_id
commit:     $commit
includes:   $included
EOF

( cd "$stage" && sha256sum $included > sha256sums.txt )

archive="$outdir/qadena-enclave-${version}-${unique_id:0:12}.tar.gz"
tar -czf "$archive" -C "$stage" .

echo "================================================"
echo "packaged: $archive"
echo "  version:   $version"
echo "  MRENCLAVE: $unique_id"
echo "  MRSIGNER:  $signer_id"
echo "  commit:    $commit"
echo "  includes:  $included"
echo "================================================"
echo ""
echo "Register this measurement by governance BEFORE installing it anywhere:"
echo "  testscripts/test_update_enclave_identity.sh $unique_id $signer_id unvalidated"
echo ""
echo "Then on each node:"
echo "  scripts/install_enclave_upgrade.sh $(basename "$archive")"
