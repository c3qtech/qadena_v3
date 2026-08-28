#!/bin/zsh
#
# Fetch the CosmWasm artifacts the Phase A gating suite needs, and VERIFY them against the
# publishers' own checksums.txt.
#
# WHY THE ARTIFACTS ARE NOT COMMITTED.  cadena_cli.sh already establishes the house pattern of
# pulling release wasm on demand rather than storing binaries in the tree.  Downloading also keeps
# the provenance honest: the checksum is verified against the release that published it, every run.
#
# WHERE cw-vesting COMES FROM -- the part most likely to be got wrong.
#
#   cw3-flex-multisig and cw4-group ship in CosmWasm/cw-plus.  cw-vesting DOES NOT.  It is a
#   DAO DAO contract (DA0-DA0/dao-contracts), and it ships in TWO BUILDS that differ by exactly one
#   capability:
#       cw_vesting-staking.wasm      declares requires_staking  -- CAN delegate
#       cw_vesting-no_staking.wasm   does not                   -- CANNOT delegate
#
#   That distinction is load-bearing for this token design.  The foundation's locked 504M is meant
#   to be delegated to consortium validators while locked, and the entire 1% inflation rationale is
#   computed against ~504M of bonded stake.  Instantiate the -no_staking build for that bucket and
#   the 504M can never be bonded: bonded stake at launch collapses to roughly the genesis
#   validator's 1,000 QDN self-bond, staker APR goes to nonsense, and chain security with it.
#   The Long-Term Reserve is the opposite case -- allocations.csv marks it `stakes: no`, so the
#   -no_staking build is the correct, smaller-surface choice there.
#
# AUDIT STATUS, recorded because the brief requires it:
#   cw-plus (cw3-flex-multisig, cw4-group)   UNAUDITED.  Its README states plainly: "None of these
#                                            contracts have been audited, and NO LIABILITY is
#                                            assumed for the use of this code."
#   dao-contracts (cw-vesting)               Audited by Oak Security, on multiple occasions.
#
#   Note the asymmetry before relying on it: the AUDITED contract holds the vesting schedules, while
#   the UNAUDITED pair is what actually custodies and moves all 4,000,000,000 QDN.

SCRIPT_DIR="${0:A:h}"
dest="$SCRIPT_DIR/token_contracts"
mkdir -p "$dest"

CW_PLUS_VERSION="v2.0.0"
DAO_VERSION="v2.7.1"

set -e

fetch() {   # fetch <url-base> <filename>
    if [ -f "$dest/$2" ]; then echo "  have $2"; return; fi
    echo "  downloading $2"
    curl -fsSL -o "$dest/$2" "$1/$2" || { echo "FAILED to download $2"; exit 1; }
}

echo "cw-plus $CW_PLUS_VERSION"
cwp="https://github.com/CosmWasm/cw-plus/releases/download/$CW_PLUS_VERSION"
fetch "$cwp" cw3_flex_multisig.wasm
fetch "$cwp" cw4_group.wasm

echo "dao-contracts $DAO_VERSION"
dao="https://github.com/DA0-DA0/dao-contracts/releases/download/$DAO_VERSION"
fetch "$dao" cw_vesting-staking.wasm
fetch "$dao" cw_vesting-no_staking.wasm

echo ""
echo "verifying against the publishers' checksums.txt"
tmp=$(mktemp -t qadena-checksums.XXXXXX); trap 'rm -f "$tmp"' EXIT INT TERM
curl -fsSL "$cwp/checksums.txt" > "$tmp"
curl -fsSL "$dao/checksums.txt" >> "$tmp"

cd "$dest"
bad=0
for f in cw3_flex_multisig.wasm cw4_group.wasm cw_vesting-staking.wasm cw_vesting-no_staking.wasm; do
    want=$(grep -E "  ${f}\$" "$tmp" | awk '{print $1}' | head -1)
    got=$(shasum -a 256 "$f" | awk '{print $1}')
    if [ -z "$want" ]; then
        echo "  !! $f: no published checksum found"; bad=1
    elif [ "$want" = "$got" ]; then
        echo "  OK $f  $got"
    else
        echo "  !! $f MISMATCH published=$want local=$got"; bad=1
    fi
done
[ "$bad" = "0" ] || { echo "checksum verification FAILED"; exit 1; }

echo ""
echo "declared capabilities (must all be present in wasmkeeper.BuiltInCapabilities()):"
for f in *.wasm; do
    printf '  %-30s ' "$f"
    strings "$f" | grep -o "requires_[a-z0-9_]*" | sort -u | tr '\n' ' '
    echo
done
