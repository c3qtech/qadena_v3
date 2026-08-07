#!/bin/zsh
#
# Install a package produced by buildscripts/package_release.sh.
#
# This is the receiving half of "build once, distribute".  Because the build is reproducible, the
# binaries here measure the same as ones built locally -- so the only thing left to establish is that
# what arrived IS what was built, which is what the checks below do before anything is written.
#
#   scripts/install_release.sh <archive.tar.gz> [--activate-enclave] [--force]
#
# The enclave is staged but NOT made current unless --activate-enclave is given.  That separation is
# deliberate: a new enclave identity must be REGISTERED and ACTIVE on chain before a node may upgrade
# to it, and those events are usually minutes apart.  Everything else (chain binary, signer, libs) is
# installed immediately, since the node is stopped anyway.
#
# NOTHING NODE-SPECIFIC IS TOUCHED: genesis, keyring, node_key, priv_validator_key, data/ and
# enclave_config/ are left exactly as they are.  A node's sealed state is migrated by its OWN old
# enclave at the next start, never copied between machines.

SCRIPT_DIR="${0:A:h}"
source "$SCRIPT_DIR/../scripts/setup_env.sh"

set -e

archive=""
activate=0
force=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --activate-enclave) activate=1; shift ;;
    --force)            force=1; shift ;;
    --help)
      echo "Usage: install_release.sh <archive.tar.gz> [--activate-enclave] [--force]"
      echo ""
      echo "  --activate-enclave  make the packaged enclave current, so the next start upgrades"
      echo "  --force             skip the on-chain registration check (NOT recommended)"
      exit 0 ;;
    *) archive="$1"; shift ;;
  esac
done

fail() { echo ""; echo "install_release.sh: $1" >&2; exit 1; }
mval() { grep "^$1:" "$stage/manifest.txt" 2>/dev/null | awk '{print $2}'; }

[[ -n "$archive" ]] || fail "no archive given.  Usage: install_release.sh <archive.tar.gz>"
[[ -f "$archive" ]] || fail "no such archive: $archive"

# The node must be DOWN: installing copies over binaries the node may be executing, and Linux refuses
# to write the image of a running process (ETXTBSY).  A half-installed node is worse than none.
if pgrep -x qadenad > /dev/null 2>&1 || pgrep -x qadenad_enclave > /dev/null 2>&1 \
   || pgrep -x signer_enclave > /dev/null 2>&1 || pgrep -f "ego-host" > /dev/null 2>&1; then
    fail "the node is still running.  Stop it first:  scripts/stop_qadena.sh --all"
fi

stage=$(mktemp -d) || fail "could not create a staging directory"
trap 'rm -rf "$stage"' EXIT INT TERM
tar -xzf "$archive" -C "$stage" || fail "could not extract $archive"
[[ -f "$stage/manifest.txt" ]] || fail "$archive has no manifest -- is it a qadena release package?"

echo "=== package ==="
sed 's/^/  /' "$stage/manifest.txt"

echo ""
echo "=== 1. the contents ARE what the manifest claims ==="
( cd "$stage" && sha256sum -c sha256sums.txt > /dev/null 2>&1 ) \
    || fail "checksum mismatch -- the archive is corrupt or was tampered with"
echo "  checksums ok"

# For a signed enclave the checksum is not enough on its own: what the chain accepts is the
# MEASUREMENT, so verify the binary measures what the manifest says it does.
check_signed() {   # file  manifest-prefix
    local f="$stage/bin/$1" pfx="$2"
    [[ -f "$f" ]] || return 0
    chmod +x "$f"
    command -v ego > /dev/null 2>&1 || fail "ego is not installed; cannot verify $1"
    local claimed actual
    claimed=$(mval "$pfx.unique_id")
    actual=$(ego uniqueid "$f" 2>/dev/null | tail -1)
    [[ "$actual" == "$claimed" ]] \
        || fail "$1 measures $actual but the manifest says $claimed"
    echo "  $1 measures $actual"
}
check_signed qadenad_enclave qadenad_enclave
check_signed signer_enclave  signer_enclave

echo ""
echo "=== 2. the enclave can still unseal what this node stored ==="
new_encl="$stage/bin/qadenad_enclave"
if [[ -f "$new_encl" ]]; then
    cur="$qadenabin/qadenad_enclave"
    new_unique=$(ego uniqueid "$new_encl" 2>/dev/null | tail -1)
    new_signer=$(ego signerid "$new_encl" 2>/dev/null | tail -1)
    new_version=$("$new_encl" -version 2>&1 | head -1)

    if [[ -x "$cur" ]]; then
        cur_signer=$(ego signerid "$cur" 2>/dev/null | tail -1)
        cur_unique=$(ego uniqueid "$cur" 2>/dev/null | tail -1)
        cur_version=$("$cur" -version 2>&1 | head -1)
        echo "  installed: $cur_version  ${cur_unique:0:16}..."
        echo "  package:   $new_version  ${new_unique:0:16}..."

        # SEALING USES THE PRODUCT KEY, derived from MRSIGNER.  A different signer unseals nothing
        # this node stored, so the upgrade would appear to succeed and leave every wallet,
        # credential and scan-window record unreadable -- with the chain still producing blocks.
        if [[ -n "$cur_signer" && "$cur_signer" != "$new_signer" ]]; then
            fail "MRSIGNER differs.
       installed: $cur_signer
       package:   $new_signer
       A different signer cannot unseal this node's state.  Refusing."
        fi
        echo "  signer unchanged -- sealed state can migrate"

        if [[ "$cur_unique" == "$new_unique" ]]; then
            echo "  same enclave already installed; nothing to upgrade"
            activate=0
        elif [[ "$cur_version" == "$new_version" ]]; then
            # check_upgrade_enclave.sh triggers on the MAIN binary's version being HIGHER, so an
            # equal version installs and then never upgrades -- silently.
            fail "package version $new_version equals the installed version, but the measurement
       differs.  check_upgrade_enclave.sh compares VERSIONS, so this would install and never
       upgrade.  Bump cmd/qadenad_enclave/version.txt and rebuild."
        fi
    else
        echo "  no enclave installed yet -- first install"
        activate=1
    fi
fi

echo ""
echo "=== 3. the chain accepts this enclave identity ==="
if [[ ! -f "$new_encl" ]]; then
    echo "  no enclave in this package -- skipped"
elif [[ $force -eq 1 ]]; then
    echo "  SKIPPED (--force)"
else
    st=$("$qadenabin/qadenad" --home "$QADENAHOME" query qadena show-enclave-identity "$new_unique" \
         --output json 2>/dev/null | jq -r '.enclaveIdentity.status' 2>/dev/null) || st=""
    if [[ -z "$st" || "$st" == "null" ]]; then
        echo "  NOT REGISTERED on chain (or the chain is unreachable from here)."
        echo "  Register it before activating:"
        echo "    testscripts/test_update_enclave_identity.sh $new_unique $new_signer unvalidated"
        # NOTE the `if`: under set -e a bare `[[ ... ]] && fail` exits the script when the test is
        # false, which would abort a perfectly good install.
        if [[ $activate -eq 1 ]]; then
            fail "refusing --activate-enclave for an unregistered identity"
        fi
    else
        echo "  registered, status: $st"
        if [[ "$st" != "active" && $activate -eq 1 ]]; then
            fail "refusing --activate-enclave while the identity is '$st'.
       The OLD enclave hands its keys only to an ACTIVE identity, so the next start would attempt
       an upgrade that cannot complete.  Promotion happens on the PROPOSER's enclave at its first
       UpdateHeight after a restart."
        fi
    fi
fi

echo ""
echo "=== 4. install ==="
mkdir -p "$qadenabin"

for f in "$stage"/bin/*(N); do
    [[ -f "$f" ]] || continue
    name=$(basename "$f")
    case "$name" in
        qadenad_enclave)
            cp "$f" "$qadenabin/qadenad_enclave.$new_unique"
            echo "  staged  qadenad_enclave.$new_unique"
            ;;
        signer_enclave)
            m=$(ego uniqueid "$f" 2>/dev/null | tail -1)
            cp "$f" "$qadenabin/signer_enclave.$m"
            cp "$f" "$qadenabin/signer_enclave"
            echo "  installed signer_enclave ($m)"
            ;;
        qadenad)
            v=$("$f" -version 2>&1 | head -1)
            cp "$f" "$qadenabin/qadenad.$v"
            cp "$f" "$qadenabin/qadenad"
            echo "  installed qadenad ($v)"
            ;;
        *)
            cp "$f" "$qadenabin/$name"
            echo "  installed $name"
            ;;
    esac
done

if [[ -d "$stage/scripts" ]]; then
    mkdir -p "$QADENAHOME/scripts"
    cp -r "$stage/scripts/." "$QADENAHOME/scripts/"
    echo "  installed scripts"
fi

if [[ -f "$new_encl" ]]; then
    if [[ $activate -eq 1 ]]; then
        cp "$new_encl" "$qadenabin/qadenad_enclave"
        echo "  ACTIVATED as the current enclave"
        echo ""
        echo "The next start performs the upgrade: the old enclave boots in --upgrade-mode and hands"
        echo "its sealed keys to the new one.  Both binaries remain on disk, which is what makes that"
        echo "possible -- do not delete the old one."
    else
        echo ""
        echo "Enclave STAGED but not activated; this node still runs its current one."
        echo "Once ${new_unique:0:16}... is ACTIVE on chain:"
        echo "  scripts/install_release.sh $archive --activate-enclave"
    fi
fi

echo ""
echo "  start with: scripts/start_qadena.sh"
