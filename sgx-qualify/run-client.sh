#!/bin/sh
# Verify a remote server (machine B).  Networked variant.  Runs OUTSIDE any enclave.
set -e
cd "$(dirname "$0")"

[ -n "$1" ] || { echo "usage: ./run-client.sh <server-ip> [--unique-id X] [--signer-id Y] [--require-production]"; exit 2; }
[ -x net/client/client ] || { echo "not built -- run ./build.sh first, or copy the client binary here"; exit 1; }

host="$1"; shift

# Verification needs collateral, which is a DIFFERENT requirement from quote generation and fails
# on a different machine.  Checked here so the two are never confused.
./check-pccs.sh > /dev/null 2>&1 || {
    echo "note: this machine's PCCS is unreachable; verification may still work from cached"
    echo "      collateral, but a fresh verification will fail.  ./check-pccs.sh for detail."
    echo
}

exec ./net/client/client --host "$host" "$@"
