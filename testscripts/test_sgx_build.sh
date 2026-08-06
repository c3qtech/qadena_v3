#!/bin/zsh
#
# Regression test for the SGX (reproducible) build.
#
# WHAT IT PROVES, AND WHY NOTHING ELSE DOES.  Every other suite runs against a debug enclave, where
# "sealing" is a string prefix and the enclave identity is whatever cmd/qadenad_enclave/*.txt says.
# None of that exercises the property the whole attestation scheme rests on:
#
#     BUILDING THE SAME SOURCE TWICE MUST PRODUCE THE SAME MEASUREMENT.
#
# MRENCLAVE (the unique id) is a hash of the built binary.  If the build is not deterministic, two
# operators building the same commit get different measurements, the enclave-identity whitelist
# cannot name a build, and an upgrade can never be approved in advance.  Nothing detects that -- the
# chain runs perfectly well on a single node with a one-off measurement; it fails only when a second
# party tries to reproduce it, which is exactly when it matters and much too late.
#
# That is why --build-reproducible was renamed --build-sgx but the reproducibility was NOT dropped:
# it is a requirement of the SGX build, not a separate option.  This suite is what keeps it true.
#
# ALSO COVERED: that the build actually yields an ego-signed binary, that use_real_enclave flips to
# TRUE for it (the positive branch of the predicate that gates every runtime script), and that
# genesis carries the real measurement rather than a placeholder.
#
# REQUIRES REAL SGX HARDWARE, ego, and docker.  It is opt-in
# (regression.sh --with-sgx) and FAILS LOUDLY rather than skipping when those are absent: a silent
# skip on a build machine would report success while proving nothing.
#
# SLOW: two full reproducible enclave builds in docker, several minutes each.  That cost is the
# test -- one build cannot demonstrate reproducibility.

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

set -e

function qadenad_alias { "$qadenabin/qadenad" --home "$QADENAHOME" "$@" }

enclave_src="$qadenabuild/cmd/qadenad_enclave"
unique_file="$enclave_src/reproducible_build_unique_id.txt"
signer_file="$enclave_src/reproducible_build_signer_id.txt"

fail() {
    echo "FAILED: $1" >&2
    exit 1
}

echo "========================="
echo "preflight"
echo "========================="
# Each of these is a hard failure, not a skip.  This suite only runs when explicitly asked for, so
# reaching it without the prerequisites means the request could not be honoured.
grep -q sgx /proc/cpuinfo 2>/dev/null \
    || fail "no SGX in /proc/cpuinfo -- this suite requires real SGX hardware (Ubuntu). Run regression.sh without --with-sgx elsewhere."
[ "$REAL_ENCLAVE" = "1" ] || fail "REAL_ENCLAVE is $REAL_ENCLAVE; setup_env.sh did not detect SGX"
command -v ego > /dev/null 2>&1 || fail "ego is not installed"
command -v docker > /dev/null 2>&1 || fail "docker is not installed"
docker info > /dev/null 2>&1 || fail "the docker daemon is not reachable; the reproducible build runs inside it"
echo "SGX present, ego $(ego uniqueid /bin/true > /dev/null 2>&1; echo ok) and docker available"

# The reproducible build refuses to run against a dirty tree -- it does `git checkout -f && git
# clean -fd` first, which would DESTROY uncommitted work.  Refuse rather than let that happen.
#
# safe.directory is supplied because this suite runs under sudo on SGX and git otherwise rejects a
# repo owned by another user with "detected dubious ownership".  That failure prints nothing to
# stdout, so an unguarded `git status --porcelain` would look exactly like a clean tree -- which is
# why the command's exit status is checked separately from its output.
tree_state=$(git -c safe.directory="$qadenabuild" -C "$qadenabuild" status --porcelain) \
    || fail "could not read git status for $qadenabuild; refusing to start a build that would 'git clean -fd' whatever is there"
[ -z "$tree_state" ] \
    || fail "the working tree has uncommitted changes; the reproducible build would run 'git clean -fd' and discard them. Commit or stash first."
echo "working tree clean"

# THE CHAIN MUST BE DOWN FOR THIS.  Installing overwrites $qadenabin/qadenad_enclave, and Linux
# refuses to write to the image of a running process with ETXTBSY -- so with the node up the build
# fails at the very last step, after several minutes, with an error that names neither the node nor
# the reason.  Stopped up front and restarted at the end, since later suites expect a running chain.
chain_was_up=0
if qadenad_alias status > /dev/null 2>&1; then
    chain_was_up=1
    echo "stopping the chain; the enclave binary cannot be replaced while it is running"
    "$qadenascripts/stop_qadena.sh" > /dev/null 2>&1 || true
    sleep 3
fi

restart_chain_if_needed() {
    [ $chain_was_up -eq 1 ] || return 0
    echo "restarting the chain"
    "$qadenascripts/start_qadena.sh" > /dev/null 2>&1 || return 0
    for _ in {1..45}; do
        qadenad_alias status > /dev/null 2>&1 && return 0
        sleep 2
    done
}
# Restarted even when an assertion fails: leaving the node down would turn one failure into every
# subsequent suite failing for an unrelated reason.
trap restart_chain_if_needed EXIT INT TERM ZERR

echo "========================="
echo "1. the SGX build produces a SIGNED enclave"
echo "========================="
"$qadenabuildscripts/build_enclave.sh" --build-sgx > /tmp/sgx_build_1.log 2>&1 \
    || { tail -20 /tmp/sgx_build_1.log >&2; fail "the first --build-sgx enclave build failed"; }

[ -f "$unique_file" ] || fail "the build produced no $unique_file"
first_unique=$(cat "$unique_file")
first_signer=$(cat "$signer_file")
[ -n "$first_unique" ] || fail "the recorded unique id is empty"
echo "measurement: $first_unique"
echo "signer:      $first_signer"

# A measurement is a 32-byte hash.  A placeholder like "unique048" reaching here would mean the
# debug branch ran despite --build-sgx.
[[ "$first_unique" =~ ^[0-9a-f]{64}$ ]] \
    || fail "unique id '$first_unique' is not a 32-byte hex measurement -- the debug branch ran instead of the SGX one"
[[ "$first_signer" =~ ^[0-9a-f]{64}$ ]] \
    || fail "signer id '$first_signer' is not a 32-byte hex measurement"

is_sgx_binary "$qadenabin/qadenad_enclave" \
    || fail "the installed enclave is not ego-signed after --build-sgx"
use_real_enclave "$qadenabin/qadenad_enclave" \
    || fail "use_real_enclave is false for a signed binary on SGX hardware -- the predicate every runtime script gates on is wrong"
echo "installed binary is signed and use_real_enclave is TRUE"

# What ego reports about the installed binary must equal what the build recorded; if these diverge,
# genesis and the whitelist are being told about a binary that is not the one installed.
installed_unique=$(ego uniqueid "$qadenabin/qadenad_enclave" 2>/dev/null)
[ "$installed_unique" = "$first_unique" ] \
    || fail "installed binary measures $installed_unique but the build recorded $first_unique"
echo "installed measurement matches the recorded one"

echo "========================="
echo "2. the build is REPRODUCIBLE -- the whole point"
echo "========================="
# Same source, second build.  A differing measurement here means the binary embeds something
# non-deterministic (a timestamp, a build path, a VCS stamp), and every guarantee that rests on
# MRENCLAVE is void: nobody else can reproduce the measurement governance approved.
"$qadenabuildscripts/build_enclave.sh" --build-sgx > /tmp/sgx_build_2.log 2>&1 \
    || { tail -20 /tmp/sgx_build_2.log >&2; fail "the second --build-sgx enclave build failed"; }

second_unique=$(cat "$unique_file")
second_signer=$(cat "$signer_file")
echo "second measurement: $second_unique"

[ "$second_unique" = "$first_unique" ] \
    || fail "THE BUILD IS NOT REPRODUCIBLE: $first_unique then $second_unique. MRENCLAVE is a hash of the binary, so nobody else can reproduce an approved measurement and enclave identities cannot be whitelisted in advance."
[ "$second_signer" = "$first_signer" ] \
    || fail "the signer id changed between builds: $first_signer then $second_signer"
echo "two independent builds of the same source produced the SAME measurement"

echo "========================="
echo "3. the old flag name still works"
echo "========================="
# --build-reproducible is kept as an alias, and the three docker Dockerfiles still pass it -- so if
# it ever stopped being accepted, the SGX build would break inside docker where the error is slow
# and awkward to find.  Checked at the parser, not with a third full build.
"$qadenabuildscripts/build_enclave.sh" --build-reproducible --help > /tmp/sgx_flag.log 2>&1 || true
grep -q "Unknown option" /tmp/sgx_flag.log \
    && fail "--build-reproducible is no longer accepted; docker_build_*/Dockerfile still pass it"
echo "--build-reproducible still accepted as an alias"

echo "========================="
echo "4. genesis names the real measurement"
echo "========================="
# build_enclave.sh rewrites enclaveIdentityList in genesis.json with the ids it just produced.  If
# that did not happen, the chain would refuse its own enclave at startup.
genesis="$QADENAHOME/config/genesis.json"
if [ -f "$genesis" ]; then
    g_unique=$(jq -r '.app_state.qadena.enclaveIdentityList[0].uniqueID' "$genesis")
    g_signer=$(jq -r '.app_state.qadena.enclaveIdentityList[0].signerID' "$genesis")
    [ "$g_unique" = "$first_unique" ] \
        || fail "genesis names uniqueID $g_unique but the built enclave measures $first_unique"
    [ "$g_signer" = "$first_signer" ] \
        || fail "genesis names signerID $g_signer but the build produced $first_signer"
    echo "genesis carries the real measurement $g_unique"
else
    echo "no genesis at $genesis yet; skipping the genesis check (run --from-genesis to cover it)"
fi

echo "========================="
echo "SGX BUILD TESTS PASSED"
echo "========================="
