#!/bin/sh
# Verify a pasted quote (machine B).  Offline variant.  Runs OUTSIDE any enclave.
set -e
cd "$(dirname "$0")"

[ -x offline/verify/verify ] || { echo "not built -- run ./build.sh first, or copy the verify binary here"; exit 1; }
exec ./offline/verify/verify "$@"
