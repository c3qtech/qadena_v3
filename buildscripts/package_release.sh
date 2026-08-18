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
# (`ego signerid $QADENAHOME/config/public.pem`).  It is packaged, and checked against the packaged
# enclave's own signer before the archive is written.
#
# BE PRECISE ABOUT WHAT IT COSTS TODAY: nothing.  keeper.InitEnclave checks SupportsUnixDomainSockets
# first, and that is hardcoded true and assigned nowhere else, so the chain always dials
# unix:///tmp/qadena_50051.sock with insecure credentials and only LOGS signerID and uniqueID.  The
# attested path -- dialRealEnclave, registered for real SGX, which verifies the enclave's remote
# report against those two IDs -- is unreachable.  add_full_node.sh has deleted public.pem since the
# first commit and nodes ran anyway for exactly this reason: run.sh passes
# "--enclave-signer-id ERROR:" (the text ego prints when the file is missing) and nothing reads it.
#
# It is shipped because install.sh ships it, it costs 621 bytes, and the day
# SupportsUnixDomainSockets stops being hardcoded, its absence stops being free.
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
DEFAULT_COMPONENTS="chain,enclave,signer,libs,scripts,config,prereqs"

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
        chain|enclave|signer|libs|scripts|config|prereqs|testscripts) ;;
        *) fail "unknown component '$c'.  Valid: chain enclave signer libs scripts config prereqs testscripts" ;;
    esac
done

# A dirty tree means the artifacts correspond to no commit, so nobody can reproduce the measurements
# -- which is the entire basis for trusting a binary you did not build yourself.  Untracked files
# count: an untracked .go file in a package IS compiled in.
#
# ONE EXCEPTION, narrow and justified: docs/static/openapi.yml.
#
# It is generated API documentation, it is NOT in any packaged component
# (chain,enclave,signer,libs,scripts,config,prereqs), and its content depends on WHICH generation
# path ran rather than on the source: proto/buf.gen.sta.yaml uses openapi_naming_strategy=simple
# while buf.gen.swagger.yaml uses fqn, and `ignite generate openapi` and the generation inside
# `ignite chain init` do not agree.  Measured 2026-08-18: the committed file is 208 KB, an aligned
# Mac regenerated 894 KB, and M1 produced a third result missing the qadena.dsvs.Msg endpoints --
# same source, same pinned plugin versions.
#
# So it dirtied the tree on every bring-up and blocked packaging for artifacts it has no part in.
# Excluding it here does not weaken the guarantee that BINARIES correspond to a commit; deciding
# which generation path is canonical is a separate question (backlog 68) and should not be settled
# by whichever machine happened to run last.
tree_state=$(cd "$qadenabuild" && git status --porcelain -- . ':(exclude)docs/static/openapi.yml')
[[ -z "$tree_state" ]] \
    || fail "the working tree is dirty; these artifacts would correspond to no commit and could not be reproduced
$tree_state"
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

# The archive gets a TOP-LEVEL DIRECTORY, so `tar xzf` in a home directory produces one tidy folder
# rather than scattering bin/, scripts/ and config/ into whatever the operator was standing in.  The
# final name depends on the version, which is not known until the binaries have been read, so stage
# under a placeholder and rename before tarring.
tmproot=$(mktemp -d) || fail "could not create a staging directory"
trap 'rm -rf "$tmproot"' EXIT INT TERM
stage="$tmproot/pkg"
mkdir -p "$stage/bin"

chain_src="$qadenabuild/cmd/qadenad/qadenad"
encl_src="$qadenabuild/cmd/qadenad_enclave/qadenad_enclave"
sign_src="$qadenabuild/cmd/signer_enclave/signer_enclave"

manifest="$stage/manifest.txt"
echo "qadena release package" > "$manifest"
echo "commit: $commit" >> "$manifest"

included=""

# Which mechanism identifies the packaged chain enclave -- set by add_binary, read by the public.pem
# check further down, which only means anything for a signed one.
enclave_identity_mode=""

# debug_id_of <binary> unique|signer -- a debug enclave's embedded identity, asked of the binary.
#
# THE TWO ENCLAVES SPELL THESE FLAGS DIFFERENTLY: qadenad_enclave takes -unique-id / -signer-id,
# signer_enclave takes -query-unique-id / -query-signer-id.  Both spellings are tried rather than
# keeping a per-binary table here, because the wrong one is free and unmistakable -- Go's flag
# package prints "flag provided but not defined" to stderr and exits 2 without starting anything, so
# a miss produces no stdout at all rather than a plausible-looking wrong answer.
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
    # THE ENCLAVE'S IDENTITY, BY WHICHEVER MECHANISM THIS BUILD USES.  An ego-signed enclave is
    # identified by its MEASUREMENT; a debug enclave by the go:embed-ed placeholder pair it prints for
    # itself with -unique-id / -signer-id.  BOTH ARE REAL IDENTITIES -- build_enclave.sh writes
    # whichever the build produced into genesis.json's enclaveIdentityList, and getEnclaveIdentity
    # looks it up by that exact string, so a node whose id differs is refused either way.  Packaging
    # it means install_release.sh can verify on arrival that the binary is the one this manifest
    # describes, which is the property that matters and is checkable without SGX.
    #
    # Requiring ego unconditionally made this script unusable for the debug path it exists to serve:
    # ego ships as an amd64-only .deb (ubuntu/setup_qadena_build.sh), so on ARM it cannot be installed
    # at all -- and there every enclave is a debug build, which has nothing for ego to read even if it
    # could be.
    if [[ "$signed" == "signed" ]]; then
        local signer mode
        if is_sgx_binary "$src"; then
            mode=sgx
            meas=$(ego uniqueid "$src" 2>/dev/null | tail -1)
            [[ "$meas" =~ ^[0-9a-f]{64}$ ]] \
                || fail "$name is not ego-signed (no measurement) -- was it built with --build-sgx?"
            signer=$(ego signerid "$src" 2>/dev/null | tail -1)
        else
            # A MACHINE THAT COULD HAVE SIGNED THIS AND DID NOT is the accidental-debug-package case
            # the old hard failure existed to catch, and it still fails.  What no longer fails is the
            # machine that could never have signed it -- not a mistake, but the debug path working.
            if [[ $REAL_ENCLAVE -eq 1 ]] && command -v ego > /dev/null 2>&1; then
                fail "$name is not ego-signed, but this machine has SGX and ego -- packaging a debug
       enclave from here is almost certainly a mistake.  Rebuild:  buildscripts/build.sh --build-sgx"
            fi
            mode=debug
            # `|| x=""` rather than a bare assignment: under set -e a non-zero function status
            # inside a command substitution kills the script before the check below can name a cause.
            meas=$(debug_id_of "$src" unique) || meas=""
            signer=$(debug_id_of "$src" signer) || signer=""
            [[ -n "$meas" && -n "$signer" ]] \
                || fail "$name reports no identity -- it is neither ego-signed nor a debug enclave
       answering -unique-id / -signer-id.  Was it built?"
            echo "  $name is a DEBUG enclave: $meas / $signer"
        fi
        if [[ "$name" == "qadenad_enclave" ]]; then
            enclave_identity_mode="$mode"
        fi
        echo "$name.identity_mode: $mode" >> "$manifest"
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

    # ONLY THESE THREE.  Everything else under config/ is the node's own -- genesis.json,
    # node_key.json, priv_validator_key.json, app.toml, config.toml -- and is written by joining, not
    # by installing.
    cp "$qadenabuild/config.yml" "$stage/config/config.yml"

    # node_params.json is shipped as the TEMPLATE, with the literal "PioneerID" that setPioneerID.sh
    # substitutes.  add_full_node.sh sed-edits this file in place and does NOT create it -- on a
    # machine with a build tree init.sh had already copied it in, which is why joining worked there
    # and failed on a machine that only ever saw a package.  install.sh only writes it when absent,
    # since after substitution it carries this node's own pioneer id.
    cp "$qadenabuild/config/node_params.json" "$stage/config/node_params.json"

    pem="$qadenabuild/cmd/qadenad_enclave/public.pem"
    [[ -f "$pem" ]] || fail "no public.pem at $pem -- run.sh derives --enclave-signer-id from it"
    cp "$pem" "$stage/config/public.pem"

    # THE PEM MUST BELONG TO THE PACKAGED ENCLAVE.  A stale public.pem produces a valid-looking node
    # that hands the chain the wrong --enclave-signer-id and is refused -- a failure that surfaces
    # only at startup on the target machine, long after this archive was built.
    #
    # ONLY FOR A SIGNED ENCLAVE.  public.pem is the signing key's public half, so on a debug build
    # there is no key, nothing signed it, and `ego signerid` has no answer -- the comparison would be
    # between two empty strings dressed up as a check.  The debug enclave's signer identity is the
    # placeholder recorded above, and it comes from the binary, not from this file.
    if want enclave && [[ "$enclave_identity_mode" == "sgx" ]]; then
        pem_signer=$(ego signerid "$pem" 2>/dev/null | tail -1)
        encl_signer=$(grep '^qadenad_enclave.signer:' "$manifest" | awk '{print $2}')
        [[ "$pem_signer" == "$encl_signer" ]] \
            || fail "public.pem signs as $pem_signer but the packaged enclave's signer is $encl_signer"
        echo "  public.pem matches the packaged enclave's signer"
    fi
    included="$included config/"
fi

if want prereqs; then
    # THE MACHINE HAS TO BE ABLE TO SATISFY ITS OWN PREREQUISITES.  ego, the SGX DCAP quote provider,
    # the PCCS configuration and the sgx/sgx_prv group membership are not things a node package can
    # install by copying files, and without them the node cannot start -- so ship the script that
    # does install them rather than leaving the operator to find it.  It is ~25KB.
    #
    # It is the BUILD setup script, so it installs Go, ignite and docker too, which a run-only node
    # does not need.  That is deliberate: one tested path beats a run-only variant that drifts out of
    # step with the real one.  install.sh only points at it, and never runs it.
    mkdir -p "$stage/ubuntu"
    cp "$qadenabuild"/ubuntu/* "$stage/ubuntu/"
    included="$included ubuntu/"
fi

if want testscripts; then
    mkdir -p "$stage/testscripts" "$stage/test_data"
    cp "$qadenabuild"/testscripts/* "$stage/testscripts/"
    cp "$qadenabuild"/test_data/* "$stage/test_data/" 2>/dev/null || true
    included="$included testscripts/"
fi

[[ -n "$included" ]] || fail "nothing selected to package (check --only)"

# THE INSTALLER TRAVELS WITH THE PACKAGE.  A target machine has the download and nothing else -- no
# checkout to run scripts/install_release.sh from -- so it ships at the package root as install.sh
# and is standalone by construction.  It is NOT checksummed with the payload and NOT on the
# installer's own allow-list: it is the thing doing the verifying, not a thing being installed.
cp "$qadenascripts/install_release.sh" "$stage/install.sh"
chmod +x "$stage/install.sh"

cat > "$stage/README.txt" <<EOF
Qadena node package

  tar xzf <this archive>
  ./<extracted directory>/install.sh

Run it as the user who will own the node, NOT with sudo: it writes only into that user's ~/qadena
and nothing in it needs root.  A sudo install leaves the whole tree root-owned, and that user's own
`qadenad q ...` then cannot read its 0600 config/client.toml.  Opening the SGX devices is a group
membership question (setup_qadena_build.sh arranges it), not a reason to install as root.

install.sh works out whether this machine needs a first install or an upgrade.  For an upgrade it
stages the new enclave beside the running one and switches only once the chain has made the new
identity ACTIVE; add --wait-active to have it wait for that and perform the cutover itself, and
--restart to start the node afterwards.

The machine needs ego (EGo 1.8.1) to run a node at all, and jq, curl and dasel to join a chain.

Contents are listed in manifest.txt and checksummed in sha256sums.txt.
EOF

checksum_all() {
    ( cd "$stage" && find bin scripts config ubuntu testscripts test_data -type f 2>/dev/null \
        | sort | xargs sha256sum > sha256sums.txt )
}
checksum_all

# --changed-since: drop components whose checksum already matches the reference manifest.  Binaries
# are large and usually all change together, so this pays off mainly for a single-component fix.
if [[ -n "$since" ]]; then
    [[ -f "$since" ]] || fail "no such reference manifest: $since"
    kept=""
    # NOT `read -r sum path`.  In zsh `path` is the array tied to $PATH, so reading into it replaces
    # the command search path and everything after this loop stops being found.
    while read -r sum entry; do
        if grep -q "^$sum  $entry\$" "$since" 2>/dev/null; then
            rm -f "$stage/$entry"
        else
            kept="$kept $(basename "$entry")"
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
pkgname="qadena-$kind-$label-$commit"
archive="$outdir/$pkgname.tar.gz"
mkdir -p "$outdir"

# Rename the placeholder to the real package name so the archive carries ONE top-level directory:
# `tar xzf` in a home directory then produces one tidy folder instead of scattering bin/, scripts/
# and config/ across whatever the operator happened to be standing in.
mv "$stage" "$tmproot/$pkgname"
tar -czf "$archive" -C "$tmproot" "$pkgname"
stage="$tmproot/$pkgname"

echo "================================================"
echo "packaged: $archive"
sed 's/^/  /' "$stage/manifest.txt"
echo "  size: $(du -h "$archive" | cut -f1)"
echo "================================================"
echo ""
if grep -q '^qadenad_enclave.unique_id:' "$stage/manifest.txt"; then
    u=$(grep '^qadenad_enclave.unique_id:' "$stage/manifest.txt" | awk '{print $2}')
    s=$(grep '^qadenad_enclave.signer:' "$stage/manifest.txt" | awk '{print $2}')
    echo "If this enclave is NEW to the chain, register it before installing anywhere:"
    echo "  testscripts/test_update_enclave_identity.sh $u $s unvalidated"
    echo ""
fi
echo "On each target node -- no checkout, no toolchain, just the download:"
echo "  tar xzf $(basename "$archive")"
echo "  ./$pkgname/install.sh"
echo "  (as the user who will own the node -- not sudo; it writes only into their ~/qadena)"
