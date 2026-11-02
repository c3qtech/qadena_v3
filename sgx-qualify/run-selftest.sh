#!/bin/sh
#
# Qualify ONE SGX machine: generate a quote in an enclave here and verify it here, as
# independently as a single box allows.  POSIX sh, no repo dependencies, like the rest of this
# directory.
#
#   ./run-selftest.sh                       everything, bringing up the PCCS if one is needed
#   ./run-selftest.sh --pccs-url https://host:8081/sgx/certification/v4/
#   ./run-selftest.sh --host <other-ip>     the real two-machine test; this box verifies only
#
# THE PCCS IS THE ONE THE FLEET RUNS: the ghcr.io/edgelesssys/pccs docker container on 8081, which
# scripts/ensure_sgx_attestation.sh starts before every real-enclave node and which needs NO Intel
# subscription key.  This script calls that script when it can reach it and inlines the same logic
# when sgx-qualify has been copied somewhere on its own.  Qualifying against an apt-installed PCCS
# instead would be qualifying against collateral plumbing the nodes do not use.
#
# WHY A SINGLE-MACHINE RUN IS WORTH ANYTHING AT ALL.  The verifier needs no SGX: eclient links
# liboehostverify and never opens /dev/sgx_*.  So the README's "two machines" is really two
# COLLATERAL PATHS, not two CPUs, and one box can play both roles -- provided the two roles are
# not quietly served from the same cached state, which is what this script arranges.
#
# AND WHAT IT STILL CANNOT PROVE: that a verifier here can resolve collateral for a platform that
# is NOT this one.  Every quote verified below comes from the same CPU whose PCK certificates the
# configured PCCS already holds.  The failure that hides is the cloud-cache asymmetry check-pccs.sh
# warns about -- an Azure cache answers for Azure machines and fails on an on-prem quote with
# OE_QUOTE_PROVIDER_CALL_ERROR while being perfectly reachable.  That is invisible from one box by
# construction, and the summary says so rather than letting a pass imply it.
#
# Options:
#   --pccs-url URL        point this machine's quote provider at an existing PCCS
#   --pccs-key KEY        ONLY for a machine with no docker at all: install an apt PCCS instead
#                         of the container the fleet uses.  Needs an Intel subscription key from
#                         https://api.portal.trustedservices.intel.com/provisioning-certification
#                         ($PCCS_API_KEY is read too).
#   --no-pccs-setup       diagnose the PCCS but change nothing; fail if it is unreachable
#   --host H              verify an enclave on another machine instead of starting one here.
#                         The only form that proves the collateral path independently.
#   --keep-cache          do NOT move the collateral cache aside.  Shows the circular result a
#                         naive self-test gives; useful exactly once, for comparison.
#   --allow-tcb-outdated  report an out-of-date TCB as a warning instead of failing
#   --skip-offline        run only the networked leg
#   --rebuild             rebuild even if the binaries are present
#   --timeout N           seconds to wait for the enclave to serve its bundle (default 90)
#   --data-dir DIR        the filesystem to check for free space (default: $HOME).  Point it at
#                         wherever the chain data will actually live.
#
# It also checks that the machine is big enough to RUN a node: at least 200GiB free on the data
# filesystem and at least 8GiB of RAM, 16GiB or more preferred.  Those are reported rather than
# fatal -- a small box can still attest, and the two findings are worth having separately.

set -e
cd "$(dirname "$0")"

INTEL_PCS="https://api.trustedservices.intel.com/sgx/certification/v4/"
# THE SAME IMAGE scripts/ensure_sgx_attestation.sh runs, so a machine is qualified against the
# collateral path its node will actually use.  Edgeless publish it preconfigured: no Intel key.
PCCS_IMAGE="ghcr.io/edgelesssys/pccs"

# THE RESOURCE FLOOR FOR RUNNING A NODE, not for this test.  Attestation itself needs almost
# nothing -- the run below would pass on a 2GB VM -- so these are checked here only because this
# script is where a machine gets qualified, and discovering the shortfall after it has been given
# a validator key costs a resync at best.
#
# They are REPORTED, NOT FATAL, for exactly that reason: a box can attest perfectly and still be
# too small, and exiting on a sizing problem would hide a working attestation behind it.
#
# Two concrete things eat the memory, beyond the OS and the node process: each enclave reserves
# its heapSize up front (cmd/qadenad_enclave 1024MB, cmd/sealprobe 512MB, cmd/signer_enclave
# 64MB), and that reservation is not shared with the host.  16GiB is preferred over the 8GiB
# floor because 8 leaves very little head-room once the chain is syncing and an enclave is live.
MIN_DISK_GIB=200
MIN_MEM_GIB=8
WANT_MEM_GIB=16

PCCS_URL=""
PCCS_KEY="${PCCS_API_KEY:-}"
PCCS_SETUP=1
REMOTE_HOST=""
KEEP_CACHE=0
TCB_STRICT=1
RUN_OFFLINE=1
REBUILD=0
TIMEOUT=90
# WHERE THE 200GiB IS MEASURED.  "200GB free" is meaningless without naming the filesystem: on
# these boxes $HOME and / are often the same device and sometimes deliberately are not, and the
# chain data is what grows.  Defaults to $HOME and the mount point is printed, so the figure can
# never be read against the wrong device.
DATA_DIR="$HOME"

while [ $# -gt 0 ]; do
    case "$1" in
        --pccs-url)          PCCS_URL="$2"; shift 2 ;;
        --pccs-key)          PCCS_KEY="$2"; shift 2 ;;
        --no-pccs-setup)     PCCS_SETUP=0; shift ;;
        --host)              REMOTE_HOST="$2"; shift 2 ;;
        --keep-cache)        KEEP_CACHE=1; shift ;;
        --allow-tcb-outdated) TCB_STRICT=0; shift ;;
        --skip-offline)      RUN_OFFLINE=0; shift ;;
        --rebuild)           REBUILD=1; shift ;;
        --timeout)           TIMEOUT="$2"; shift 2 ;;
        --data-dir)          DATA_DIR="$2"; shift 2 ;;
        # DERIVED FROM THE HEADER, not a fixed line range: a range silently starts printing
        # shell code the moment the comment block grows, which is exactly what it did.
        --help|-h)           awk 'NR<2{next} /^#/{sub(/^# ?/,""); print; next} {exit}' "$0"; exit 0 ;;
        *) echo "unknown option: $1  (--help)"; exit 2 ;;
    esac
done

# `sudo` only where it is actually needed, and not at all when already root, so the privileged
# steps are visible one at a time instead of the whole script running elevated.
SUDO=""
[ "$(id -u)" -eq 0 ] || SUDO="sudo"

SRV_PID=""
SRV_LOG=""
MOVED=""
TMPCACHE=""
RC=0

say()  { echo "$@"; }
head1() { echo; echo "=== $*"; }
pass() { echo "  ok    $*"; }
warn() { echo "  warn  $*"; }
bad()  { echo "  FAIL  $*"; RC=1; }

# EVERYTHING IS PUT BACK, whatever happens.  The cache is MOVED rather than deleted (below), the
# enclave runs as a child of this shell, and both must survive a ^C or a mid-run failure.
cleanup() {
    if [ -n "$SRV_PID" ] && kill -0 "$SRV_PID" 2>/dev/null; then
        kill "$SRV_PID" 2>/dev/null || true
        wait "$SRV_PID" 2>/dev/null || true
    fi
    for m in $MOVED; do
        orig=$(echo "$m" | sed 's/\.selftest-aside$//')
        [ -e "$m" ] && [ ! -e "$orig" ] && mv "$m" "$orig" 2>/dev/null || true
    done
    [ -n "$MOVED" ] && echo "restored the collateral cache"
    [ -n "$TMPCACHE" ] && rm -rf "$TMPCACHE" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------------------------------------
head1 "0. platform"
# ---------------------------------------------------------------------------------------------
say "  $(uname -s) $(uname -m), $(uname -r)"

if [ -z "$REMOTE_HOST" ]; then
    # Only the ENCLAVE half has platform requirements.  With --host this box is just a verifier,
    # which needs no SGX at all, so none of this applies and skipping it is not a leniency.
    [ "$(uname -s)" = "Linux" ] && [ "$(uname -m)" = "x86_64" ] || {
        say ""
        say "The enclave half runs only on x86_64 Linux.  To use this box as the VERIFIER for an"
        say "enclave elsewhere -- which needs no SGX -- pass --host <that machine>."
        exit 1; }

    [ -c /dev/sgx_enclave ] || {
        bad "/dev/sgx_enclave is missing: no enclave can be created here."
        say "        Install the SGX driver/DCAP packages (ubuntu/setup_qadena_build.sh does this)."
        exit 1; }
    pass "/dev/sgx_enclave present"

    # THE sgx_prv TRAP, which this repo has already paid for twice.  /dev/sgx_provision is
    # root:sgx_prv -- a DIFFERENT group from /dev/sgx_enclave's.  Missing only the second, an
    # enclave starts and runs perfectly and fails REMOTE ATTESTATION later, far from anything that
    # names a permission (see the comment block in ubuntu/setup_qadena_build.sh).
    #
    # THE STANDARD NAME IS ALWAYS CHECKED, the group the device reports only ADDS to it: udev does
    # not retroactively re-apply a new rule to a device node that already existed at boot, so
    # /dev/sgx_provision can still be carrying its pre-DCAP group -- a plausible-looking value that
    # trusting alone is exactly how this was missed before.
    if [ ! -c /dev/sgx_provision ]; then
        bad "/dev/sgx_provision is missing: quote GENERATION will fail (verification would not)."
        say "        It is created by libsgx-dcap-default-qpl's udev rule; a reboot may be needed."
    else
        pass "/dev/sgx_provision present"
        prv_grps="sgx_prv"
        dev_grp=$(stat -c %G /dev/sgx_provision 2>/dev/null || echo "")
        case "$dev_grp" in
            ""|root|sgx_prv) ;;
            *) prv_grps="$prv_grps $dev_grp" ;;
        esac
        my_grps=$(id -nG 2>/dev/null || echo "")
        for g in $prv_grps; do
            if ! getent group "$g" > /dev/null 2>&1; then
                warn "group $g does not exist yet (it ships with the DCAP packages)"
            elif echo "$my_grps" | tr ' ' '\n' | grep -qx "$g"; then
                pass "$(id -un) is in $g"
            else
                bad "$(id -un) is NOT in $g -- quote generation will fail here."
                say "        sudo usermod -aG $g $(id -un)   then start a NEW login session:"
                say "        group changes do not apply to the session that made them."
            fi
        done
    fi
    [ $RC -eq 0 ] || { say ""; say "Fix the above first: nothing below can succeed."; exit 1; }

    # ----- size.  Past this point RC is 0, so a shortfall below marks the run without aborting
    # it, and the attestation result is still obtained in the same pass.
    mem_kib=$(awk '/^MemTotal:/{print $2}' /proc/meminfo 2>/dev/null)
    if [ -z "$mem_kib" ]; then
        warn "could not read /proc/meminfo; memory not checked"
    else
        mem_gib=$(awk -v k="$mem_kib" 'BEGIN{printf "%.1f", k/1048576}')
        mem_int=$((mem_kib / 1048576))
        if [ "$mem_int" -lt "$MIN_MEM_GIB" ]; then
            bad "${mem_gib}GiB of RAM, below the ${MIN_MEM_GIB}GiB minimum for running a node."
            say "        ${WANT_MEM_GIB}GiB or more is preferred.  Each enclave reserves its heap"
            say "        up front (1024MB for the chain enclave alone), so this is not head-room"
            say "        the node can borrow back."
        elif [ "$mem_int" -lt "$WANT_MEM_GIB" ]; then
            pass "${mem_gib}GiB of RAM (meets the ${MIN_MEM_GIB}GiB minimum)"
            warn "${WANT_MEM_GIB}GiB or more is PREFERRED: at ${mem_gib}GiB there is little"
            say "        head-room once the chain is syncing and an enclave holds its reserved heap."
        else
            pass "${mem_gib}GiB of RAM (${WANT_MEM_GIB}GiB+ preferred, met)"
        fi
    fi

    # df -P for the single-line POSIX format: without it a long device name wraps and $4/$6 land
    # on the wrong fields.
    _df=$(df -P -k "$DATA_DIR" 2>/dev/null | awk 'NR==2{print $4" "$6}')
    if [ -z "$_df" ]; then
        warn "could not read free space for $DATA_DIR; disk not checked"
    else
        disk_kib=${_df%% *}
        disk_mnt=${_df##* }
        disk_gib=$(awk -v k="$disk_kib" 'BEGIN{printf "%.0f", k/1048576}')
        disk_int=$((disk_kib / 1048576))
        if [ "$disk_int" -lt "$MIN_DISK_GIB" ]; then
            bad "${disk_gib}GiB free on $disk_mnt (holding $DATA_DIR), below the ${MIN_DISK_GIB}GiB minimum."
            say "        The chain data grows here.  If it will live on another device, point"
            say "        --data-dir at that one instead."
        else
            pass "${disk_gib}GiB free on $disk_mnt (${MIN_DISK_GIB}GiB minimum, met)"
        fi
    fi
fi

# EGo IS ONLY NEEDED FOR THE ENCLAVE HALF.  With --host this box verifies, and the README's whole
# point is that a verifier needs no enclave -- the client binary can simply have been copied here.
# Demanding `ego` of it would reject the one configuration that closes the gap section 5 names.
if [ -z "$REMOTE_HOST" ]; then
    command -v ego > /dev/null 2>&1 || { say "ego not found -- install EGo first"; exit 1; }
fi

# ---------------------------------------------------------------------------------------------
head1 "1. quote provider (PCCS)"
# ---------------------------------------------------------------------------------------------
# VERIFICATION, NOT ONLY GENERATION, NEEDS THIS.  Both legs below depend on collateral, and on a
# fresh machine the stock conf points at https://localhost:8081 -- misconfigured out of the box
# while looking entirely normal.
pccs_ok() { ./check-pccs.sh > /dev/null 2>&1; }

# pccs_url as the conf actually has it.  check-pccs.sh parses it with a grep rather than a JSON
# parse because the stock file carries // comments; same reason here.
conf_pccs_url() {
    grep -oE '"pccs_url"[[:space:]]*:[[:space:]]*"[^"]*"' /etc/sgx_default_qcnl.conf 2>/dev/null \
        | head -1 | sed 's/.*:[[:space:]]*"//; s/"$//'
}

if [ -n "$PCCS_URL" ]; then
    say "pointing the quote provider at $PCCS_URL"
    $SUDO ./check-pccs.sh --install-url "$PCCS_URL"
fi

if pccs_ok; then
    ./check-pccs.sh | sed 's/^/  /'
elif [ "$PCCS_SETUP" -eq 0 ]; then
    ./check-pccs.sh | sed 's/^/  /' || true
    say ""
    say "PCCS unreachable and --no-pccs-setup was given."
    exit 1
else
    ./check-pccs.sh | sed 's/^/  /' || true
    say ""
    # A VERIFIER NEEDS NO PCCS, and telling one to install a PCCS -- which needs an Intel
    # subscription key -- sends it after the wrong half.  pccs_url serves PCK-CERTIFICATE
    # retrieval, which only quote GENERATION does; verification needs collateral (TCB info, QE
    # identity, CRLs), and those endpoints on Intel's PCS are public and keyless.  That is exactly
    # why both of Qadena's shipped confs set collateral_service to Intel rather than to a cache.
    if [ -n "$REMOTE_HOST" ]; then
        say "--- no reachable PCCS -- but this box is the VERIFIER only, so it does not need one."
        say ""
        say "    sudo apt install -y libsgx-dcap-default-qpl"
        say "    sudo ./check-pccs.sh --install-url $INTEL_PCS"
        say ""
        say "That points collateral_service at Intel's PCS, which serves verification collateral"
        say "without any key.  It also sets pccs_url, which is unused here: PCK certificates are"
        say "fetched only when generating a quote, and this box generates none."
        exit 1
    fi

    say "--- no reachable PCCS; bringing one up"

    # AZURE NEEDS NOTHING.  Mirrors scripts/ensure_sgx_attestation.sh: with the Azure DCAP client
    # installed, attestation goes through it and there is no PCCS to run.
    if dpkg -V az-dcap-client > /dev/null 2>&1; then
        pass "az-dcap-client is installed -- attestation goes through Azure DCAP, no PCCS needed"
    else
        # THE HOUSE PCCS IS A DOCKER CONTAINER, NOT AN APT PACKAGE, and it needs NO Intel
        # subscription key: scripts/ensure_sgx_attestation.sh runs ghcr.io/edgelesssys/pccs on
        # 8081 and every real-enclave node on this fleet starts that way (run.sh calls it before
        # `qadenad start`).  Qualifying a machine against an apt-installed PCCS would be
        # qualifying it against collateral plumbing the nodes do not use -- and would demand a key
        # for no reason.
        #
        # PREFER THE REPO SCRIPT when it is reachable, so there is one source of truth for the
        # image, the port and the health probe.  sgx-qualify is meant to be copyable to a bare
        # machine on its own, though, so the same logic is inlined below for when it is not.
        HOUSE="../scripts/ensure_sgx_attestation.sh"
        if [ -x "$HOUSE" ] && command -v zsh > /dev/null 2>&1; then
            say "using the fleet's own $HOUSE"
            "$HOUSE" || { bad "ensure_sgx_attestation.sh could not bring up attestation"; exit 1; }
        elif command -v docker > /dev/null 2>&1; then
            say "standalone copy: bringing up $PCCS_IMAGE directly (same image and port)"
            if docker container ls -a --format '{{.Names}}' 2>/dev/null | grep -qx pccs; then
                if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx pccs; then
                    # Up but not answering -- the state the house script restarts rather than
                    # recreates, because the container holds the cache it has already fetched.
                    say "the pccs container is up but not answering; restarting it"
                    docker stop pccs > /dev/null 2>&1 || true
                    docker start pccs > /dev/null 2>&1 || true
                else
                    say "starting the existing pccs container"
                    docker start pccs > /dev/null 2>&1 \
                        || { bad "could not start the existing pccs container"; exit 1; }
                fi
            else
                say "no pccs container yet; creating one"
                docker run -p 8081:8081 --name pccs -d "$PCCS_IMAGE" > /dev/null \
                    || { bad "docker run failed."
                         say "        If this is a permission error, add yourself to the docker"
                         say "        group and start a NEW login session: docker needs it, and"
                         say "        group changes never apply to the session that made them."
                         exit 1; }
            fi
        elif [ -n "$PCCS_KEY" ]; then
            # LAST RESORT, and deliberately last: an apt PCCS is not what the nodes run.  Kept
            # only for a machine with no docker at all.
            say "no docker; falling back to an apt-installed PCCS (not what the fleet runs)"
            if ! apt-cache policy sgx-dcap-pccs 2>/dev/null | grep -q 'Candidate: [0-9]'; then
                say "adding the Intel SGX apt repository"
                $SUDO mkdir -p /etc/apt/keyrings
                wget -qO- https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key \
                    | $SUDO tee /etc/apt/keyrings/intel-sgx-keyring.asc > /dev/null
                echo "deb [signed-by=/etc/apt/keyrings/intel-sgx-keyring.asc arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu $(lsb_release -cs) main" \
                    | $SUDO tee /etc/apt/sources.list.d/intel-sgx.list > /dev/null
                $SUDO apt-get update
            fi
            $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y sgx-dcap-pccs
            PCCS_CONF=/opt/intel/sgx-dcap-pccs/config/default.json
            if [ -f "$PCCS_CONF" ]; then
                # The key goes into the config the PACKAGE shipped: its key set has changed
                # between versions and overwriting it wholesale would drop what this one needs.
                $SUDO cp "$PCCS_CONF" "$PCCS_CONF.bak.$$"
                if command -v jq > /dev/null 2>&1; then
                    _pj=$(mktemp)
                    $SUDO cat "$PCCS_CONF.bak.$$" | jq --arg k "$PCCS_KEY" '.ApiKey = $k' > "$_pj"
                    $SUDO cp "$_pj" "$PCCS_CONF"; rm -f "$_pj"
                else
                    $SUDO sed -i 's|"ApiKey"[[:space:]]*:[[:space:]]*"[^"]*"|"ApiKey": "'"$PCCS_KEY"'"|' "$PCCS_CONF"
                fi
                $SUDO systemctl enable --now pccs || true
            else
                say "$PCCS_CONF does not exist, so the package's own interactive setup has not run."
                say "This script will not fake answers to it.  Run whichever it provides:"
                for s in /opt/intel/sgx-dcap-pccs/install.sh \
                         /opt/intel/sgx-dcap-pccs/container/pccs_install.sh; do
                    [ -f "$s" ] && say "    sudo $s"
                done
                exit 1
            fi
        else
            say ""
            say "No PCCS is reachable and one cannot be brought up here."
            say ""
            say "The fleet runs the PCCS as a docker container and needs NO Intel key"
            say "(scripts/ensure_sgx_attestation.sh).  Install docker and re-run:"
            say "    sudo apt install -y docker.io"
            say "    sudo usermod -aG docker $(id -un)      # then a NEW login session"
            say ""
            say "Or point at a PCCS that already exists on your network:"
            say "    ./run-selftest.sh --pccs-url https://<host>:8081/sgx/certification/v4/"
            say ""
            say "An apt-installed PCCS is also possible but is NOT what the nodes use, and needs a"
            say "key from https://api.portal.trustedservices.intel.com/provisioning-certification :"
            say "    ./run-selftest.sh --pccs-key <key>"
            exit 1
        fi

        # ONLY REWRITE THE CONF IF IT IS NOT ALREADY RIGHT.  ubuntu/sgx_default_qcnl.conf already
        # points pccs_url at localhost:8081, which is where the container listens, so on a
        # Qadena-provisioned machine there is nothing to change -- and rewriting it anyway would
        # churn a file this script does not own and reset collateral_service needlessly.
        case "$(conf_pccs_url)" in
            *localhost:8081*|*127.0.0.1:8081*)
                say "the quote provider already points at localhost:8081; leaving the conf alone" ;;
            *)
                $SUDO ./check-pccs.sh --install-url https://localhost:8081/sgx/certification/v4/ ;;
        esac
    fi

    # The container takes a few seconds to bind, and its first call also fetches from Intel.
    i=0
    while [ $i -lt 40 ]; do
        pccs_ok && break
        i=$((i + 1)); sleep 2
    done
    if pccs_ok; then
        pass "PCCS is answering"
    else
        bad "the PCCS still does not answer"
        say ""
        say "What it logged:"
        if docker ps -a --format '{{.Names}}' 2>/dev/null | grep -qx pccs; then
            docker logs --tail 30 pccs 2>&1 | sed 's/^/        /'
        else
            $SUDO journalctl -u pccs -n 30 --no-pager 2>/dev/null | sed 's/^/        /' \
                || say "        (no pccs container and no pccs unit)"
        fi
        exit 1
    fi
fi

# ---------------------------------------------------------------------------------------------
head1 "2. build"
# ---------------------------------------------------------------------------------------------
if [ -n "$REMOTE_HOST" ]; then
    # As a pure verifier this box needs only the client, which plain `go` builds.
    if [ "$REBUILD" -eq 1 ] || [ ! -x net/client/client ]; then
        command -v ego > /dev/null 2>&1 || {
            say "  net/client/client is not built here and EGo is absent."
            say "  Either install EGo and ./build.sh, or copy net/client/client from the machine"
            say "  that built it -- it needs no enclave, only /opt/ego/lib at runtime."
            exit 1; }
        ./build.sh
    else
        say "  net/client/client present (--rebuild to force)"
    fi
elif [ "$REBUILD" -eq 1 ] || [ ! -x net/server/server ] || [ ! -x net/client/client ] \
     || [ ! -x offline/attest/attest ] || [ ! -x offline/verify/verify ]; then
    ./build.sh
else
    say "  binaries present (--rebuild to force)"
fi

# PINNED FROM THE BINARY, NEVER TYPED.  Reading the measurements out of the artefact that is about
# to run is what makes this a gate rather than an inspection, and it cannot drift the way a value
# pasted from an earlier build can.  With --host there is nothing local to measure, so the client
# prints the remote measurements for the operator to compare instead.
PIN=""
if [ -z "$REMOTE_HOST" ]; then
    MRENCLAVE=$(ego uniqueid net/server/server)
    MRSIGNER=$(ego signerid net/server/server)
    say "  MRENCLAVE $MRENCLAVE"
    say "  MRSIGNER  $MRSIGNER"
    PIN="--unique-id $MRENCLAVE --signer-id $MRSIGNER"
fi

# --require-production ALWAYS.  A debug-signed enclave produces a perfectly valid quote and its
# memory is not confidential, so a run that does not assert this qualifies nothing.
GATES="--require-production"
[ "$TCB_STRICT" -eq 1 ] && GATES="$GATES --require-tcb-uptodate"

# ---------------------------------------------------------------------------------------------
head1 "3. collateral cache"
# ---------------------------------------------------------------------------------------------
# THIS IS THE WHOLE POINT OF THE SCRIPT.  Generation and verification are separate capabilities
# that happen to be satisfiable from one on-disk cache, so a self-test over a warm cache can pass
# while a real remote verifier fails.  The QCNL searches $AZDCAP_CACHE, $XDG_CACHE_HOME, $HOME,
# $TMPDIR and /tmp for a .dcap-qcnl directory (documented in ubuntu/sgx_default_qcnl.conf), so
# every one of them has to go, not just the first.
#
# MOVED, NOT DELETED.  On a working node that cache is populated and re-fetching it costs real
# time; discarding someone's cache is not this script's call.  cleanup() puts it back.
#
# CAVEAT: this moves the cache of THIS user, which is what in-process quote generation (EGo's
# default) uses.  If generation here goes out-of-process through QGS/aesmd, the cache that matters
# belongs to that daemon's account and is untouched -- a warm-cache result would then still be
# possible, and only a verifier in a different account or container rules it out.
if [ "$KEEP_CACHE" -eq 1 ]; then
    warn "keeping the collateral cache (--keep-cache): a pass below may be circular"
else
    TMPCACHE=$(mktemp -d)
    for d in "${AZDCAP_CACHE:-}" "${XDG_CACHE_HOME:-}" "$HOME" "${TMPDIR:-}" /tmp; do
        [ -n "$d" ] || continue
        c="$d/.dcap-qcnl"
        [ -d "$c" ] || continue
        if mv "$c" "$c.selftest-aside" 2>/dev/null; then
            MOVED="$MOVED $c.selftest-aside"
            say "  moved aside $c"
        else
            warn "could not move $c -- a pass may be served from it"
        fi
    done
    [ -n "$MOVED" ] || say "  no .dcap-qcnl cache found; collateral will be fetched fresh anyway"
    # First in the search order, and empty, so anything written during this run lands here and is
    # thrown away with it.
    export AZDCAP_CACHE="$TMPCACHE"
    say "  AZDCAP_CACHE=$TMPCACHE (empty, discarded afterwards)"
fi

# ---------------------------------------------------------------------------------------------
head1 "4. networked leg"
# ---------------------------------------------------------------------------------------------
if [ -n "$REMOTE_HOST" ]; then
    say "verifying the enclave on $REMOTE_HOST (this box is the verifier only)"
    TARGET="$REMOTE_HOST"
else
    SRV_LOG=$(mktemp)
    say "starting the enclave server"
    # shellcheck disable=SC2086
    ego run ./net/server/server > "$SRV_LOG" 2>&1 &
    SRV_PID=$!
    TARGET="127.0.0.1"

    # WAIT FOR THE BUNDLE, do not sleep a guess: the first GetRemoteReport on a cold cache fetches
    # PCK certificates and can take tens of seconds.  And watch the child, so an enclave that dies
    # reports ITS error instead of a connection refusal from the client.
    i=0
    ready=0
    while [ $i -lt "$TIMEOUT" ]; do
        if ! kill -0 "$SRV_PID" 2>/dev/null; then
            bad "the enclave server exited before serving its bundle:"
            sed 's/^/        /' "$SRV_LOG"
            rm -f "$SRV_LOG"
            exit 1
        fi
        if curl -s -m 2 -o /dev/null "http://127.0.0.1:8080/attest" 2>/dev/null; then
            ready=1; break
        fi
        i=$((i + 2)); sleep 2
    done
    if [ "$ready" -ne 1 ]; then
        bad "the enclave did not serve its attestation bundle within ${TIMEOUT}s"
        sed 's/^/        /' "$SRV_LOG"
        rm -f "$SRV_LOG"
        exit 1
    fi
    pass "enclave is serving its quote ($(wc -l < "$SRV_LOG" | tr -d ' ') lines logged)"
fi

say ""
# shellcheck disable=SC2086
if ./net/client/client --host "$TARGET" $PIN $GATES; then
    pass "networked leg PASSED"
else
    bad "networked leg FAILED"
fi

if [ -n "$SRV_LOG" ]; then
    say ""
    say "enclave server log:"
    sed 's/^/        /' "$SRV_LOG"
    rm -f "$SRV_LOG"
fi
if [ -n "$SRV_PID" ]; then
    kill "$SRV_PID" 2>/dev/null || true
    wait "$SRV_PID" 2>/dev/null || true
    SRV_PID=""
fi

# ---------------------------------------------------------------------------------------------
if [ "$RUN_OFFLINE" -eq 1 ] && [ -z "$REMOTE_HOST" ]; then
head1 "5. offline leg (nonce-bound)"
# ---------------------------------------------------------------------------------------------
# WHAT THIS ADDS over the networked leg: freshness.  A quote carries no timestamp, so one produced
# without a challenge shows only that the machine could produce a valid quote at SOME point --
# possibly before a downgrade.  The networked leg binds the TLS certificate, which is not the same
# thing: a relayed bundle would fail the cert check, but a replayed standalone quote would not.
NONCE=$(./offline/verify/verify --new-nonce)
say "  nonce $NONCE"
QUOTE=$(mktemp)
if ego run ./offline/attest/attest --nonce "$NONCE" > "$QUOTE" 2> "$QUOTE.err"; then
    sed 's/^/        /' "$QUOTE.err"
    say ""
    # shellcheck disable=SC2086
    if ./offline/verify/verify --nonce "$NONCE" --quote-file "$QUOTE" \
            --unique-id "$(ego uniqueid offline/attest/attest)" \
            --signer-id "$(ego signerid offline/attest/attest)" $GATES; then
        pass "offline leg PASSED"
    else
        bad "offline leg FAILED"
    fi
else
    bad "could not produce a quote:"
    sed 's/^/        /' "$QUOTE.err"
fi
rm -f "$QUOTE" "$QUOTE.err"
fi

# ---------------------------------------------------------------------------------------------
head1 "summary"
# ---------------------------------------------------------------------------------------------
if [ $RC -eq 0 ]; then
    say "PASS -- this machine generates DCAP quotes and they verify here from fresh collateral."
else
    say "FAIL -- see above.  GetRemoteReport failing is a GENERATION problem (quote provider,"
    say "/dev/sgx_provision, sgx_prv); VerifyRemoteReport failing is a VERIFICATION problem on"
    say "this host (collateral, /etc/sgx_default_qcnl.conf).  A TCB status other than UpToDate is"
    say "neither: the quote is genuine and the platform needs microcode or PSW updates, which is"
    say "exactly what a remote relying party would reject."
    say ""
    say "A memory or disk shortfall is none of the above: attestation is fine and the machine is"
    say "simply too small to run a node.  Read section 0 to tell them apart."
fi
say ""
say "NOT PROVEN, and not provable from one box: that a verifier here can resolve collateral for a"
say "platform other than this one.  Every quote above came from the CPU whose PCK certificates the"
say "configured PCCS already holds.  To close it, run the client against a different machine --"
say "    ./run-selftest.sh --host <other-machine>"
say "which needs no SGX on this side, so any x86-64 Linux box with /opt/ego/lib will do."
exit $RC
