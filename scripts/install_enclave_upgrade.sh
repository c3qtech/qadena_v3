#!/bin/zsh
#
# Install an enclave package produced by buildscripts/package_enclave_upgrade.sh.
#
# This is the receiving half of "build once, distribute": the reproducible build means the binary in
# the archive measures the same as one built locally, so the only thing that matters is proving the
# artifact you received IS that binary -- which is what the checks below do before touching anything.
#
#   scripts/install_enclave_upgrade.sh <archive.tar.gz> [--activate] [--force]
#
# Without --activate the new enclave is installed ALONGSIDE the current one and nothing changes until
# you activate it.  That separation is deliberate: the identity has to be ACTIVE on chain before a
# node may upgrade to it, and the two events are usually minutes apart.
#
# WHAT IT REFUSES, AND WHY EACH ONE COST SOMETHING TO LEARN:
#
#   node still running      installing copies over the binary the enclave is executing, which fails
#                           with ETXTBSY -- and a half-copied enclave is worse than none
#   measurement mismatch    the archive's manifest must match `ego uniqueid` of the binary inside it
#   signer mismatch         a different MRSIGNER cannot unseal what the current enclave sealed, so
#                           the upgrade would hand over nothing and every wallet, credential and scan
#                           record would be unreadable -- with the chain still producing blocks
#   not registered/active   the OLD enclave refuses to hand its keys to an identity the chain does
#                           not list as active: "couldn't find an active enclave identity"
#   version not newer       check_upgrade_enclave.sh triggers on the MAIN binary's version being
#                           HIGHER; equal or lower installs silently and never upgrades

SCRIPT_DIR="${0:A:h}"
source "$SCRIPT_DIR/../scripts/setup_env.sh"

set -e

archive=""
activate=0
force=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --activate) activate=1; shift ;;
    --force)    force=1; shift ;;
    --help)
      echo "Usage: install_enclave_upgrade.sh <archive.tar.gz> [--activate] [--force]"
      echo ""
      echo "  --activate  also make it the main enclave, so the next start performs the upgrade"
      echo "  --force     skip the on-chain registration check (NOT recommended)"
      exit 0 ;;
    *) archive="$1"; shift ;;
  esac
done

fail() { echo ""; echo "install_enclave_upgrade.sh: $1" >&2; exit 1; }

[[ -n "$archive" ]] || fail "no archive given.  Usage: install_enclave_upgrade.sh <archive.tar.gz>"
[[ -f "$archive" ]] || fail "no such archive: $archive"

# The node must be DOWN.  install copies over $qadenabin/qadenad_enclave, and Linux refuses to write
# the image of a running process.
if pgrep -x qadenad > /dev/null 2>&1 || pgrep -x qadenad_enclave > /dev/null 2>&1 \
   || pgrep -f "ego-host.*qadenad_enclave" > /dev/null 2>&1; then
    fail "the node is still running.  Stop it first:  scripts/stop_qadena.sh --all"
fi

stage=$(mktemp -d) || fail "could not create a staging directory"
trap 'rm -rf "$stage"' EXIT INT TERM
tar -xzf "$archive" -C "$stage" || fail "could not extract $archive"

[[ -f "$stage/manifest.txt" ]] || fail "$archive has no manifest -- is it a qadena enclave package?"
[[ -f "$stage/qadenad_enclave" ]] || fail "$archive contains no qadenad_enclave"
chmod +x "$stage/qadenad_enclave" "$stage/qadenad" 2>/dev/null || true

m_unique=$(grep '^unique_id:' "$stage/manifest.txt" | awk '{print $2}')
m_signer=$(grep '^signer_id:' "$stage/manifest.txt" | awk '{print $2}')
m_version=$(grep '^version:' "$stage/manifest.txt" | awk '{print $2}')

echo "=== package ==="
echo "  version:   $m_version"
echo "  MRENCLAVE: $m_unique"
echo "  MRSIGNER:  $m_signer"

echo ""
echo "=== 1. the binary IS what the manifest claims ==="
( cd "$stage" && sha256sum -c sha256sums.txt > /dev/null 2>&1 ) \
    || fail "checksum mismatch -- the archive is corrupt or was tampered with"
echo "  checksums ok"

command -v ego > /dev/null 2>&1 || fail "ego is not installed on this node"
actual_unique=$(ego uniqueid "$stage/qadenad_enclave" 2>/dev/null | tail -1)
actual_signer=$(ego signerid "$stage/qadenad_enclave" 2>/dev/null | tail -1)
[[ "$actual_unique" == "$m_unique" ]] \
    || fail "the binary measures $actual_unique but the manifest says $m_unique"
echo "  measurement matches: $actual_unique"

echo ""
echo "=== 2. the SIGNER is unchanged, so sealed state can migrate ==="
current="$qadenabin/qadenad_enclave"
if [[ -x "$current" ]]; then
    cur_signer=$(ego signerid "$current" 2>/dev/null | tail -1)
    cur_unique=$(ego uniqueid "$current" 2>/dev/null | tail -1)
    cur_version=$("$current" -version 2>&1 | head -1)
    echo "  installed now: $cur_version  $cur_unique"

    if [[ -n "$cur_signer" && "$cur_signer" != "$actual_signer" ]]; then
        fail "MRSIGNER differs.
       installed: $cur_signer
       package:   $actual_signer
       Sealing uses the PRODUCT key, which is derived from MRSIGNER -- a different signer cannot
       unseal anything this node has stored.  The upgrade would appear to succeed and leave every
       wallet, credential and scan record unreadable, with the chain still producing blocks."
    fi
    echo "  signer unchanged"

    if [[ "$cur_unique" == "$actual_unique" ]]; then
        fail "this exact enclave is already installed ($actual_unique); nothing to do"
    fi

    # check_upgrade_enclave.sh compares versions, so a package that is not NEWER installs and then
    # never upgrades -- silently.
    if [[ "$cur_version" == "$m_version" ]]; then
        fail "package version $m_version equals the installed version.
       check_upgrade_enclave.sh triggers on the main binary's version being HIGHER, so this would
       install and then never upgrade.  Bump cmd/qadenad_enclave/version.txt and rebuild."
    fi
else
    echo "  no enclave installed yet -- treating this as a first install"
fi

echo ""
echo "=== 3. the chain accepts this identity ==="
if [[ $force -eq 1 ]]; then
    echo "  SKIPPED (--force).  If it is not active, the old enclave will refuse the handover."
else
    st=$("$qadenabin/qadenad" --home "$QADENAHOME" query qadena show-enclave-identity "$actual_unique" \
         --output json 2>/dev/null | jq -r '.enclaveIdentity.status' 2>/dev/null)
    if [[ -z "$st" || "$st" == "null" ]]; then
        fail "$actual_unique is not registered on chain.
       Register it first, from a node that can reach the chain:
         testscripts/test_update_enclave_identity.sh $actual_unique $actual_signer unvalidated
       (pass --force to install anyway; the upgrade will fail until it is active)"
    fi
    echo "  registered, status: $st"
    if [[ "$st" != "active" ]]; then
        echo "  NOTE: not active yet.  The old enclave hands its keys over only to an ACTIVE identity."
        echo "        Promotion happens on the PROPOSER's enclave at its first UpdateHeight after a"
        echo "        restart, so restarting the proposing validator is what triggers it."
        [[ $activate -eq 1 ]] && fail "refusing --activate while the identity is '$st'; activating now
       would make the next start attempt an upgrade that cannot complete"
    fi
fi

echo ""
echo "=== 4. install ==="
mkdir -p "$qadenabin"
cp "$stage/qadenad_enclave" "$qadenabin/qadenad_enclave.$actual_unique"
echo "  installed $qadenabin/qadenad_enclave.$actual_unique"

if [[ -f "$stage/qadenad" ]]; then
    cp "$stage/qadenad" "$qadenabin/qadenad"
    echo "  installed $qadenabin/qadenad (chain binary)"
fi

if [[ $activate -eq 1 ]]; then
    cp "$stage/qadenad_enclave" "$qadenabin/qadenad_enclave"
    echo "  activated as the main enclave"
    echo ""
    echo "Next start performs the upgrade: the OLD enclave boots in --upgrade-mode and hands its"
    echo "sealed keys to the new one.  Both binaries stay on disk, which is what makes that possible."
    echo "  scripts/start_qadena.sh"
else
    echo ""
    echo "NOT activated.  The node still runs its current enclave."
    echo "Once $actual_unique is ACTIVE on chain, activate and restart:"
    echo "  scripts/install_enclave_upgrade.sh $archive --activate"
fi
