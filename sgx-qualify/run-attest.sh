#!/bin/sh
# Produce a quote as pasteable text (machine A).  Offline variant.
set -e
cd "$(dirname "$0")"

[ -x offline/attest/attest ] || { echo "not built -- run ./build.sh first"; exit 1; }

./check-pccs.sh || {
    echo
    echo "Refusing to run: quote generation needs a reachable PCCS (see above)."
    exit 1
}

echo
echo "MRENCLAVE: $(ego uniqueid offline/attest/attest)"
echo "MRSIGNER:  $(ego signerid offline/attest/attest)"
echo
exec ego run ./offline/attest/attest "$@"
