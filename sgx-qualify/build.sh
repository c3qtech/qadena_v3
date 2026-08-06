#!/bin/sh
#
# Build both qualification tools.  POSIX sh, no repo dependencies -- this directory is meant to be
# copied to a bare machine on its own.
#
# The two ENCLAVE binaries are built with ego-go and signed; the two VERIFIER binaries are built with
# plain go, because they run outside any enclave and on a different machine.  Mixing that up is the
# usual first mistake: `ego run` on a verifier fails in a way that reads like an attestation problem.

set -e

cd "$(dirname "$0")"

# THE SAME EGo QADENA INSTALLS.  ubuntu/setup_qadena_build.sh pins this exact version, and the
# toolchain is part of the measurement: a different EGo produces a different MRENCLAVE from identical
# source, so a machine qualified with one version has not been qualified for the other.
EGO_VERSION=1.8.1

# ego installs Go under /opt/ego/go and does not always put it on PATH; a plain `go` may be missing
# entirely on a machine provisioned only for building enclaves.
if ! command -v go > /dev/null 2>&1; then
    for d in /usr/local/go/bin /opt/ego/go/bin; do
        [ -x "$d/go" ] && PATH="$d:$PATH" && export PATH && break
    done
fi
command -v ego    > /dev/null 2>&1 || { echo "ego not found -- install EGo first"; exit 1; }
command -v ego-go > /dev/null 2>&1 || { echo "ego-go not found -- install EGo first"; exit 1; }
command -v go     > /dev/null 2>&1 || { echo "go not found (looked in /usr/local/go/bin and /opt/ego/go/bin)"; exit 1; }

ego_have=$(ego version 2>&1 | sed -n 's/.*version=\([0-9.]*\).*/\1/p' | head -1)
echo "ego:    ${ego_have:-unknown} (qadena pins $EGO_VERSION)"
echo "go:     $(go version)"
if [ -n "$ego_have" ] && [ "$ego_have" != "$EGO_VERSION" ]; then
    echo
    echo "WARNING: this is EGo $ego_have but qadena installs $EGO_VERSION."
    echo "         Measurements produced here will not match a qadena-provisioned machine."
    echo "         Install the pinned version:"
    echo "           wget https://github.com/edgelesssys/ego/releases/download/v$EGO_VERSION/ego_${EGO_VERSION}_amd64_ubuntu-22.04.deb"
    echo "           sudo apt install -y ./ego_${EGO_VERSION}_amd64_ubuntu-22.04.deb"
    echo
fi
echo

# A COMMITTED signing key, so MRSIGNER is the same on every machine.
#
# Generating one per machine -- which this used to do -- makes MRSIGNER differ everywhere, so a
# fleet cannot be checked against one --signer-id and two machines building identical source produce
# unrelated identities.  For a qualification tool that is the wrong trade.
#
# THIS KEY IS NOT A SECRET AND MUST NEVER SIGN A PRODUCTION ENCLAVE.  It is in the repository so the
# measurements are predictable; anyone can sign an enclave with it.  Qadena's real enclave key is a
# separate, deliberately committed key for the same reason (cmd/qadenad_enclave/private.pem).
if [ ! -f signing-key.pem ]; then
    echo "signing-key.pem is missing -- it is committed to the repo; restore it or measurements will not match other machines"
    exit 1
fi

# DEPENDENCIES ARE VENDORED, so this builds with no network at all.  That is not tidiness: the
# offline variant exists for machines with no network path, and requiring proxy.golang.org to build
# the tool that tests them would defeat it.  -mod=vendor is explicit so a stray GOFLAGS cannot
# quietly send the build to the network instead.
MOD="-mod=vendor"

# REPRODUCIBILITY FLAGS, so the same source measures the same on every machine.  Without them the
# binary embeds the build path (/home/alvillarica/... vs /home/azureuser/...) and VCS state, and
# MRENCLAVE differs between machines that built identical code -- which defeats pinning --unique-id
# across a fleet.  These mirror what buildscripts/build_enclave.sh does for the chain enclave.
#
# Reproducibility still requires the SAME Go and EGo versions on both machines; the toolchain is an
# input to the measurement.  build.sh checks EGo above and prints Go, so a mismatch is visible.
export SOURCE_DATE_EPOCH=1710000000
export CFLAGS="-Wdate-time -D__DATE__=\"fixed\" -D__TIME__=\"fixed\""
BUILDFLAGS="-trimpath -buildvcs=false"
LDFLAGS="-s -w"

# THE VERIFIER HALVES NEED OPEN ENCLAVE'S HOST HEADERS.  eclient wraps liboehostverify via cgo, and
# a plain `go build` cannot find them:
#
#     fatal error: openenclave/attestation/verifier.h: No such file or directory
#
# EGo ships them under /opt/ego, but does not put them on the default cgo search path.  This is only
# needed for the OUTSIDE-the-enclave binaries; ego-go already knows where its own headers live.
OE_CFLAGS="-I/opt/ego/include"
OE_LDFLAGS="-L/opt/ego/lib"

echo "building the networked pair..."
ego-go build $MOD $BUILDFLAGS -ldflags="$LDFLAGS" -o net/server/server ./net/server
ego sign enclave-server.json
CGO_CFLAGS="$OE_CFLAGS" CGO_LDFLAGS="$OE_LDFLAGS" go build $MOD $BUILDFLAGS -ldflags="$LDFLAGS" -o net/client/client ./net/client

echo "building the offline pair..."
ego-go build $MOD $BUILDFLAGS -ldflags="$LDFLAGS" -o offline/attest/attest ./offline/attest
ego sign enclave-attest.json
CGO_CFLAGS="$OE_CFLAGS" CGO_LDFLAGS="$OE_LDFLAGS" go build $MOD $BUILDFLAGS -ldflags="$LDFLAGS" -o offline/verify/verify ./offline/verify

echo
echo "enclave measurements (record these; verifiers pin them):"
echo "  server MRENCLAVE: $(ego uniqueid net/server/server)"
echo "  attest MRENCLAVE: $(ego uniqueid offline/attest/attest)"
echo "  MRSIGNER (both):  $(ego signerid net/server/server)"
echo
echo "networked:  ego run ./net/server/server        (enclave machine)"
echo "            ./net/client/client --host <ip>    (other machine)"
echo "offline:    ./offline/verify/verify --new-nonce"
echo "            ego run ./offline/attest/attest --nonce <n>   > quote.txt"
echo "            ./offline/verify/verify --nonce <n> --quote-file quote.txt"
