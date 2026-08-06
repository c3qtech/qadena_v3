#!/bin/sh
# Run the attested server (machine A).  Networked variant.
set -e
cd "$(dirname "$0")"

[ -x net/server/server ] || { echo "not built -- run ./build.sh first"; exit 1; }

# Preflight, because a PCCS problem surfaces as a GetRemoteReport error naming neither the PCCS nor
# the URL, and that is the single most common reason this fails on a fresh machine.
./check-pccs.sh || {
    echo
    echo "Refusing to start: quote generation needs a reachable PCCS (see above)."
    echo "Override with --force if you want to see the raw failure."
    [ "$1" = "--force" ] || exit 1
}

echo
echo "MRENCLAVE: $(ego uniqueid net/server/server)"
echo "MRSIGNER:  $(ego signerid net/server/server)"
echo "give those to the client with --unique-id / --signer-id"
echo
exec ego run ./net/server/server
