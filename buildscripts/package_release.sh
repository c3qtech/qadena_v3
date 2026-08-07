#!/bin/zsh
#
# Package a complete set of built artifacts for installation on other nodes.
#
# WHY THIS EXISTS.  Building on every machine costs a ~24 minute reproducible docker build per node
# and needs docker, ego and the whole toolchain everywhere.  The build is reproducible -- the same
# commit measures the same on every machine, which this repo verifies -- so a binary built once and
# copied is EQUIVALENT to one built locally.  Build once, distribute, verify on arrival.
#
# WHAT IS PACKAGED: everything buildscripts/install.sh puts on a node, which is the authority on
# what a running node actually needs.  Binaries alone are NOT enough, and the two easiest omissions
# both fail late rather than loudly:
#
#   chain    qadenad
#   enclave  qadenad_enclave, the signed SGX enclave
#   signer   signer_enclave, the signed SGX signer enclave
#   libs     libwasmvm*.so -- qadenad links these at LOAD time and will not even start without them
#   scripts  scripts/* -- run.sh, start_qadena.sh, add_full_node.sh and the rest
#   config   config.yml and public.pem, described below
#
# public.pem is the ENCLAVE SIGNER'S PUBLIC KEY.  run.sh derives --enclave-signer-id from it
# (`ego signerid $QADENAHOME/config/public.pem`), so a node without it cannot start, and a node with
# the WRONG one starts and is refused by the chain.  It is packaged, and checked against the
# packaged enclave's own signer before the archive is written.
#
# config.yml carries minimum-gas-prices, which add_full_node.sh and convert_to_validator.sh read
# when writing app.toml.  Without it, joining fails.
#
# testscripts is available via --only but is NOT in the default set: a node does not need the test
# suite to run, and it pulls in test_data with it.
#
# WHAT IS NEVER PACKAGED: anything node-specific.  genesis.json belongs to the chain and is fetched
# when joining; enclave_params_<id>.json is SEALED to one machine's enclave; keyring, node_key,
# priv_validator_key, app.toml and config.toml are that node's own identity and settings.  Copying
# any of them between machines either fails to unseal or moves secrets somewhere they were never
# meant to be.
#
#   ./buildscripts/package_release.sh [--out DIR]
#                                     [--only chain,enclave,signer,libs,scripts,config,testscripts]
#                                     [--changed-since <manifest.txt>]
#
# --changed-since produces an UPDATE: only components whose checksum differs from that manifest are
# included.  Useful when a change touches one component -- an enclave-only fix should not push a
# 210MB chain binary to every node.

SCRIPT_DIR="${0:A:h}"
source "$SCRIPT_DIR/../scripts/setup_env.sh"

set -e

outdir="."
only=""
since=""

# The default set is "what a node needs to run".  testscripts is deliberately outside it.
DEFAULT_COMPONENTS="chain,enclave,signer,libs,scripts,config"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out)   [[ -n "$2" && "$2" != --* ]] || { echo "--out requires a directory"; exit 1; }; outdir="$2"; shift 2 ;;
    --only)  [[ -n "$2" && "$2" != --* ]] || { echo "--only requires a list"; exit 1; }; only="$2"; shift 2 ;;
    --changed-since) [[ -n "$2" && "$2" != --* ]] || { echo "--changed-since requires a manifest"; exit 1; }; since="$2"; shift 2 ;;
    --help)
      sed -n '2,44p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

fail() { echo "package_release.sh: $1" >&2; exit 1; }

selected="${only:-$DEFAULT_COMPONENTS}"
want() { echo ",$selected," | grep -q ",$1,"; }

for c in ${(s:,:)selected}; do
    case "$c" in
        chain|enclave|signer|libs|scripts|config|testscripts) ;;
        *) fail "unknown component '$c'.  Valid: chain enclave signer libs scripts config testscripts" ;;
    esac
done

# A dirty tree means the artifacts correspond to no commit, so nobody can reproduce the measurements
# -- which is the entire basis for trusting a binary you did not build yourself.  Untracked files
# count: an untracked .go file in a package IS compiled in.
[[ -z "$(cd "$qadenabuild" && git status --porcelain)" ]] \
    || fail "the working tree is dirty; these artifacts would correspond to no commit and could not be reproduced"
commit=$(cd "$qadenabuild" && git rev-parse --short HEAD)

# HEAD IS NOT NECESSARILY THE COMMIT THESE BINARIES WERE BUILT FROM.  Packaging usually happens some
# commits after the build -- adding this very script moves HEAD without recompiling anything.
# Recording HEAD blindly would claim a measurement for a commit that was never built, and the first
# person to try reproducing it would hit a mismatch they cannot explain.
#
# Rather than guess which commits "affect the build" (buildscripts/ sometimes does and sometimes does
# not, and getting that wrong is the same false claim in a subtler form), just compare timestamps and
# say so.  The operator knows whether the intervening commits mattered; the script does not.
head_time=$(cd "$qadenabuild" && git log -1 --format=%ct HEAD)
stale=0

stage=$(mktemp -d) || fail "could not create a staging directory"
trap 'rm -rf "$stage"' EXIT INT TERM
mkdir -p "$stage/bin"

chain_src="$qadenabuild/cmd/qadenad/qadenad"
encl_src="$qadenabuild/cmd/qadenad_enclave/qadenad_enclave"
sign_src="$qadenabuild/cmd/signer_enclave/signer_enclave"

manifest="$stage/manifest.txt"
echo "qadena release package" > "$manifest"
echo "commit: $commit" >> "$manifest"

included=""

add_binary() {   # name src [signed]
    local name="$1" src="$2" signed="$3"
    [[ -x "$src" ]] || fail "$name not built at $src -- build it first"

    # Built BEFORE the commit being recorded means this artifact is not from that commit.
    local mtime
    mtime=$(stat -c %Y "$src" 2>/dev/null || stat -f %m "$src" 2>/dev/null || echo 0)
    if [[ "$mtime" -gt 0 && "$mtime" -lt "$head_time" ]]; then
        echo "  WARNING: $name is older than HEAD ($commit) -- it was built from an earlier commit." >&2
        stale=1
    fi

    # THE TWO BINARIES ANSWER DIFFERENTLY.  qadenad is a cobra command, so it wants the `version`
    # SUBCOMMAND -- `-version` gets you "unknown shorthand flag: 'v'", which then sails on into the
    # manifest as the version string.  It also links libwasmvm at load time, so it cannot even start
    # without the library on the path.  The enclaves are plain binaries with a -version flag.
    local ver meas=""
    if [[ "$name" == "qadenad" ]]; then
        ver=$(LD_LIBRARY_PATH="$qadenabin:$(dirname "$src")" "$src" version 2>/dev/null | head -1)
        [[ -n "$ver" ]] || fail "$name would not report its version -- is libwasmvm missing from $qadenabin?"
    else
        ver=$("$src" -version 2>&1 | head -1)
    fi
    if [[ "$signed" == "signed" ]]; then
        command -v ego > /dev/null 2>&1 || fail "ego is not installed; cannot verify $name is signed"
        meas=$(ego uniqueid "$src" 2>/dev/null | tail -1)
        [[ "$meas" =~ ^[0-9a-f]{64}$ ]] \
            || fail "$name is not ego-signed (no measurement) -- was it built with --build-sgx?"
        local signer
        signer=$(ego signerid "$src" 2>/dev/null | tail -1)
        echo "$name.signer: $signer" >> "$manifest"
    fi
    cp "$src" "$stage/bin/$name"
    echo "$name.version: $ver" >> "$manifest"
    if [[ -n "$meas" ]]; then
        echo "$name.unique_id: $meas" >> "$manifest"
    fi
    included="$included $name"
}

# Each of these is an `if`, not `want x && add_binary ...`: under set -e a false `want` would make the
# && list return non-zero and kill the script, so --only enclave would "fail" by doing its job.
if want chain;   then add_binary qadenad         "$chain_src";          fi
if want enclave; then add_binary qadenad_enclave "$encl_src" signed;    fi
if want signer;  then add_binary signer_enclave  "$sign_src" signed;    fi

if want libs; then
    # install.sh takes these from vendor, which is the authoritative copy; the other two locations
    # are where a previous install left them.  (N) yields an empty list rather than a zsh
    # "no matches found" error when a location has none.
    for lib in "$qadenabuild"/vendor/github.com/CosmWasm/wasmvm/v2/internal/api/*.so(N) \
               "$qadenabuild"/cmd/qadenad/libwasmvm*.so(N) "$qadenabin"/libwasmvm*.so(N); do
        [[ -f "$lib" ]] || continue
        b=$(basename "$lib")
        [[ -f "$stage/bin/$b" ]] && continue     # first location wins
        cp "$lib" "$stage/bin/$b"
        included="$included $b"
    done
    [[ -n "$(echo "$stage"/bin/*.so(N))" ]] \
        || fail "no libwasmvm*.so found -- qadenad links these at load time and will not start without them"
fi

if want scripts; then
    mkdir -p "$stage/scripts"
    cp "$qadenabuild"/scripts/* "$stage/scripts/"
    included="$included scripts/"
fi

if want config; then
    mkdir -p "$stage/config"

    # ONLY THESE TWO.  Everything else under config/ is the node's own -- genesis.json, node_key.json,
    # priv_validator_key.json, app.toml, config.toml -- and is written by joining, not by installing.
    cp "$qadenabuild/config.yml" "$stage/config/config.yml"

    pem="$qadenabuild/cmd/qadenad_enclave/public.pem"
    [[ -f "$pem" ]] || fail "no public.pem at $pem -- run.sh derives --enclave-signer-id from it and the node cannot start without it"
    cp "$pem" "$stage/config/public.pem"

    # THE PEM MUST BELONG TO THE PACKAGED ENCLAVE.  A stale public.pem produces a valid-looking node
    # that hands the chain the wrong --enclave-signer-id and is refused -- a failure that surfaces
    # only at startup on the target machine, long after this archive was built.
    if want enclave; then
        pem_signer=$(ego signerid "$pem" 2>/dev/null | tail -1)
        encl_signer=$(grep '^qadenad_enclave.signer:' "$manifest" | awk '{print $2}')
        [[ "$pem_signer" == "$encl_signer" ]] \
            || fail "public.pem signs as $pem_signer but the packaged enclave's signer is $encl_signer"
        echo "  public.pem matches the packaged enclave's signer"
    fi
    included="$included config/"
fi

if want testscripts; then
    mkdir -p "$stage/testscripts" "$stage/test_data"
    cp "$qadenabuild"/testscripts/* "$stage/testscripts/"
    cp "$qadenabuild"/test_data/* "$stage/test_data/" 2>/dev/null || true
    included="$included testscripts/"
fi

[[ -n "$included" ]] || fail "nothing selected to package (check --only)"

checksum_all() {
    ( cd "$stage" && find bin scripts config testscripts test_data -type f 2>/dev/null \
        | sort | xargs sha256sum > sha256sums.txt )
}
checksum_all

# --changed-since: drop components whose checksum already matches the reference manifest.  Binaries
# are large and usually all change together, so this pays off mainly for a single-component fix.
if [[ -n "$since" ]]; then
    [[ -f "$since" ]] || fail "no such reference manifest: $since"
    kept=""
    while read -r sum path; do
        if grep -q "^$sum  $path\$" "$since" 2>/dev/null; then
            rm -f "$stage/$path"
        else
            kept="$kept $(basename "$path")"
        fi
    done < "$stage/sha256sums.txt"
    [[ -n "$kept" ]] || fail "nothing changed since $since -- no update needed"
    checksum_all
    included="$kept"
    echo "update.since: $(basename "$since")" >> "$manifest"
fi

echo "includes:$included" >> "$manifest"
if [[ $stale -eq 1 ]]; then
    # Recorded IN the manifest, not just printed here, because the person verifying the measurement
    # months from now reads the manifest and never sees this terminal.
    echo "commit.caveat: artifacts predate HEAD; they were built from an earlier commit" >> "$manifest"
fi

label=$(grep '^qadenad.version:' "$manifest" | awk '{print $2}')
[[ -n "$label" ]] || label="$commit"
kind=$([[ -n "$since" ]] && echo update || echo full)
archive="$outdir/qadena-$kind-$label-$commit.tar.gz"
mkdir -p "$outdir"
tar -czf "$archive" -C "$stage" .

echo "================================================"
echo "packaged: $archive"
sed 's/^/  /' "$manifest"
echo "  size: $(du -h "$archive" | cut -f1)"
echo "================================================"
echo ""
if grep -q '^qadenad_enclave.unique_id:' "$manifest"; then
    u=$(grep '^qadenad_enclave.unique_id:' "$manifest" | awk '{print $2}')
    s=$(grep '^qadenad_enclave.signer:' "$manifest" | awk '{print $2}')
    echo "If this enclave is NEW to the chain, register it before installing anywhere:"
    echo "  testscripts/test_update_enclave_identity.sh $u $s unvalidated"
    echo ""
fi
echo "On each target node:"
echo "  scripts/install_release.sh $(basename "$archive")"
