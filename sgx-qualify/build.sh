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

echo "ego:    $(ego version 2>&1 | head -1)"
echo "go:     $(go version)"
echo

# One signing key for both enclaves, so they share a MRSIGNER.  Generated on first build and kept:
# regenerating it changes MRSIGNER and invalidates any --signer-id you have written down.
if [ ! -f private.pem ]; then
    echo "generating a signing key (private.pem) -- keep it if you pin --signer-id"
    openssl genrsa -out private.pem -3 3072 2>/dev/null
fi

echo "building the networked pair..."
ego-go build -o net/server/server ./net/server
ego sign enclave-server.json
go build -o net/client/client ./net/client

echo "building the offline pair..."
ego-go build -o offline/attest/attest ./offline/attest
ego sign enclave-attest.json
go build -o offline/verify/verify ./offline/verify

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
