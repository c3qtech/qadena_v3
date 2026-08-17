#!/bin/zsh
#
# Reset the chain to a fresh genesis WITHOUT rebuilding the binaries.
#
# reset_qadena.sh runs a full init, which on SGX means three reproducible docker builds and roughly
# twenty minutes.  Almost all of that is rebuilding code that did not change.  When you only want the
# chain back at height 0 -- after a test run, a bad migration, a wedged upgrade -- this does the same
# reset in a fraction of the time by reusing the binaries already built in the repo.
#
# WHAT IT DOES NOT DO: build anything.  If cmd/qadenad/qadenad or cmd/qadenad_enclave/qadenad_enclave
# are missing, or the code changed since they were built, use reset_qadena.sh (or init.sh) instead.
# init.sh --skip-build refuses rather than guessing, so this fails loudly rather than resetting to a
# stale binary.
#
# THE ENCLAVE IDENTITY IS RE-DERIVED FROM THE INSTALLED BINARY, so a fresh genesis names the enclave
# that will actually run -- signed measurement on SGX, the embedded test ids in debug.  That is the
# step people miss when resetting by hand: wiping $QADENAHOME and re-running `ignite chain init`
# leaves config.yml's literal test-unique-id in genesis, and the chain then refuses its own enclave
# with an error naming neither.
#
# ONE CAVEAT.  `ignite chain init` stamps the CURRENT git commit into genesis as app_version, while
# the installed binaries are whatever was built earlier.  If you have committed since the last build,
# genesis will name a commit newer than the code actually running.  Harmless for a test reset and
# worth knowing before reading anything into that field -- if it matters, rebuild instead.
#
#   ./buildscripts/reset_qadena_fast.sh --advertise-ip-address <ip> [--with-setup] [--no-start]
#
# --with-setup additionally provisions the secdsvs user, matching reset_qadena.sh.

SCRIPT_DIR="${0:A:h}"
source "$SCRIPT_DIR/../scripts/setup_env.sh"

ADVERTISE_IP_ADDRESS=""
with_setup=0
no_start=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --advertise-ip-address)
      if [[ -n "$2" && "$2" != --* ]]; then
        ADVERTISE_IP_ADDRESS="$2"; shift 2
      else
        echo "Error: --advertise-ip-address requires an IP argument"; exit 1
      fi
      ;;
    --with-setup) with_setup=1; shift ;;
    --no-start)   no_start=1; shift ;;
    --help)
      echo "Usage: reset_qadena_fast.sh --advertise-ip-address <ip> [--with-setup] [--no-start]"
      echo ""
      echo "Resets the chain to a fresh genesis WITHOUT rebuilding.  Use reset_qadena.sh if the"
      echo "code changed and the binaries need rebuilding."
      exit 0
      ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

if [[ -z "$ADVERTISE_IP_ADDRESS" ]] ; then
    ADVERTISE_IP_ADDRESS=`$qadenabuildscripts/get_default_ip.sh 2>/dev/null`
    [[ -n "$ADVERTISE_IP_ADDRESS" ]] \
        || { echo "Error: --advertise-ip-address is required (could not determine a default)"; exit 1; }
    echo "Using $ADVERTISE_IP_ADDRESS as the advertised address"
fi

# init.sh REFUSES to run as root while the SGX runtime scripts REQUIRE it, so this script spans two
# identities and has to change between them -- exactly as testscripts/regression.sh does.  Getting it
# wrong is silent: inside `sudo -u <user>`, SUDO_USER is set to ROOT and setup_env.sh would resolve
# QADENAHOME to /root/qadena, resetting a chain nothing else ever looks at.  -i runs a login shell so
# the toolchain stays on PATH; ignite and go are usually only there.
run_init() {
    if [[ $(id -u) -ne 0 || -z "$SUDO_USER" ]] ; then
        "$qadenabuildscripts/init.sh" --skip-build --advertise-ip-address "$ADVERTISE_IP_ADDRESS"
        return $?
    fi

    local user_home
    user_home=$(getent passwd "$SUDO_USER" 2>/dev/null | cut -d: -f6)
    [[ -n "$user_home" ]] || { echo "could not resolve the home directory of $SUDO_USER"; return 1; }
    if [[ "$user_home/qadena" != "$QADENAHOME" ]] ; then
        echo "refusing to run init.sh as $SUDO_USER: it would use $user_home/qadena, not $QADENAHOME"
        return 1
    fi

    # Root-owned leftovers from previous runs stop init.sh -- running as the user -- from deleting
    # $QADENAHOME, and its fallback is a nested sudo that stops to ask for a password.  Cleared here
    # while still root; --advertise-ip-address has already announced the directory is going.
    case "$QADENAHOME" in
        /*/qadena) rm -rf "$QADENAHOME" 2>/dev/null ;;
        *) echo "refusing to remove \$QADENAHOME=$QADENAHOME: not an absolute path ending in /qadena"; return 1 ;;
    esac
    [[ -d "$qadenabuild/.git" ]] && chown -R "$SUDO_USER" "$qadenabuild" 2>/dev/null

    echo "running init.sh as $SUDO_USER via a login shell (it refuses to run as root)"
    sudo -u "$SUDO_USER" -i -- env -u SUDO_USER \
        "$qadenabuildscripts/init.sh" --skip-build --advertise-ip-address "$ADVERTISE_IP_ADDRESS"
}

echo "========================================"
echo "FAST RESET -- no rebuild"
echo "  $QADENAHOME will be erased"
echo "========================================"

echo "Stopping the chain..."
if ! "$qadenascripts/stop_qadena.sh" --all ; then
    echo "stop_qadena.sh reported failure; refusing to reset on top of a running node"
    exit 1
fi

# Confirmed independently: something can restart a process after the script has finished
# checking, and resetting underneath a live node corrupts both.  (The run_enclave.sh /
# run_signerenclave.sh respawn loops this once guarded against are gone -- qadenad spawns its
# enclaves now -- but qadenad_enclave/signer_enclave still match the qadenad pattern.)
leftover=$(pgrep -af "qadenad|ego-host|signer_enclave" 2>/dev/null \
           | grep -v "reset_qadena_fast" || true)
if [[ -n "$leftover" ]] ; then
    echo "processes still alive after stop_qadena.sh:"
    echo "$leftover"
    exit 1
fi

echo "Re-initializing genesis (no rebuild)..."
if ! run_init ; then
    echo "init.sh --skip-build failed; the chain has NOT been reset cleanly"
    exit 1
fi

# --no-start leaves the node down.  Useful for comparing the result against a full init: a running
# chain immediately creates enclave_config, enclave_data, wasm/ and addrbook.json, so a freshly
# started node never looks like a freshly initialised one no matter how correct the reset was.
if [[ $no_start -eq 1 ]] ; then
    echo "--no-start: leaving the node stopped"
else
    echo "Starting the chain..."
    if ! "$qadenascripts/start_qadena.sh" ; then
        echo "start_qadena.sh failed"
        exit 1
    fi
fi

if [[ $with_setup -eq 1 && $no_start -eq 1 ]] ; then
    echo "--with-setup ignored: the node was not started (--no-start)"
elif [[ $with_setup -eq 1 ]] ; then
    echo "Waiting for the chain to produce blocks before provisioning secdsvs..."
    for i in {1..45} ; do
        "$qadenabin/qadenad" --home "$QADENAHOME" status > /dev/null 2>&1 && break
        sleep 2
    done
    "$qadenatestscripts/setup.sh" --specific-user secdsvs \
        || { echo "setup.sh --specific-user secdsvs failed"; exit 1; }
fi

echo "========================================"
echo "FAST RESET DONE"
echo "========================================"
