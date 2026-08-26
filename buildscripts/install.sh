#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

# install scripts
# get flags --enclave-only, --chain-only, --scripts-only
install_enclave=0
install_signer_enclave=0
install_chain=0
install_scripts=0
install_provider_scripts=0
install_testscripts=0
hold=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --enclave)
            install_enclave=1
            shift
            ;;
        --signer-enclave)
            install_signer_enclave=1
            shift
            ;;
        --chain)
            install_chain=1
            shift
            ;;
        --scripts)
            install_scripts=1
            shift
            ;;
        --provider-scripts)
            install_provider_scripts=1
            shift
            ;;
        --testscripts)
            install_testscripts=1
            shift
            ;;
        --hold)
            # HOLD THE NEW BINARY BACK.  Install qadenad_enclave.<uniqueID> but leave the LIVE
            # binary alone, so the node keeps running what it is running and nothing has to stop.
            #
            # This is the only correct order on real SGX, where MRENCLAVE is a hash of the built
            # image and therefore CANNOT be known before the build: build --hold, read the
            # measurement off the artifact (ego uniqueid), register it by governance, wait for it to
            # go active, and only then let the scheduled swap put it in service at the plan height.
            #
            # Swapping first is what leaves a node down: the old enclave refuses to hand its sealed
            # keys to a measurement the chain has not made active.
            hold=1
            shift
            ;;
        --all)
            install_enclave=1
            install_signer_enclave=1
            install_chain=1
            install_scripts=1
            install_provider_scripts=1
            install_testscripts=1
            shift
            ;;
        --help)
            echo "Usage: install.sh [--enclave] [--signer-enclave] [--chain] [--scripts] [--provider-scripts] [--testscripts] [--all] [--hold]"
            echo "  --hold  install qadenad_enclave.<uniqueID> only; do not replace the live binary"
            echo "          (and do not stop the node).  Required on SGX, where the measurement is"
            echo "          only knowable after the build.  Deploy it as a governance plan:"
            echo "          build.sh --release, commit, then roll the fleet."
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# need at least one
if [[ $install_enclave -eq 0  && $install_signer_enclave -eq 0 && $install_chain -eq 0 && $install_scripts -eq 0 && $install_testscripts -eq 0 && $install_provider_scripts -eq 0 ]]; then
    echo "Error: Need at least one option: --enclave, --signer-enclave, --chain, --scripts, --provider-scripts, or --all"
    exit 1
fi

# INSTALLING A BINARY OVER A RUNNING NODE SILENTLY DOES NOTHING.
#
# These were plain `cp`, unchecked.  Copying to qadenad_enclave.<uniqueID> succeeds (a new filename
# is never busy) while copying to the LIVE qadenad_enclave fails with "Text file busy" -- and with
# the error discarded, the build prints "Install done" and exits 0 while the node keeps running the
# OLD binary.  Every other signal says the deploy worked.
#
# That cost two separate debugging sessions on 2026-08-21: a staged qadenad_enclave.unique049
# appeared next to an unchanged live binary, and the mismatch was only found by hashing them.
#
# So: stop the node before touching any binary, refuse to continue if it will not stop, and check
# every copy.  Scripts and test data are NOT binaries and do not require this -- installing those
# over a running node is fine and is done routinely.
#
# THE NODE IS LEFT STOPPED.  Restarting is the caller's decision, because the caller is usually
# doing something else next -- run.sh performs the enclave upgrade check on the way up, and starting
# here would race it.
node_stopped=0

# count_procs <exact-process-name> -- how many are running, printed as a bare integer, always.
#
# NOT `pgrep -c`.  That is a Linux-only (procps) flag: BSD pgrep on macOS rejects it, prints its
# usage to stderr and NOTHING to stdout, so `$(( $(pgrep -cx qadenad) + ... ))` became `$(( + ))`
# and the shell died with "bad math expression" -- taking init.sh down with it before a single
# binary was installed.  This ran fine on the Linux fleet for months and only broke on a Mac.
#
# `pgrep -x <name> | wc -l` is the portable spelling.  Note pgrep exits 1 when there are no
# matches, which under `set -e` would be fatal even though "nothing is running" is the outcome we
# WANT -- hence the `|| true`.  `-x` (exact COMM match) is on both platforms and keeps this from
# matching the ssh/shell command line that mentions the name, which `-f` would.
count_procs() {
    local n
    n=$( { pgrep -x "$1" 2>/dev/null || true; } | wc -l | tr -d '[:space:]' )
    printf "%s" "${n:-0}"
}

ensure_stopped_for_binaries() {
    [[ $node_stopped -eq 1 ]] && return 0

    # NEVER INSIDE THE BUILD CONTAINER.  build.sh re-invokes itself with DOCKER_BUILD=1 for the SGX
    # reproducible build, and that inner invocation does not carry --hold.  A build container has no
    # node to stop -- but the SGX builder is privileged and bind-mounts $QADENAHOME (it needs
    # /dev/sgx), so stop_qadena.sh reached out of the container and stopped the REAL node on the
    # host, halting a chain at height 98145 during what was supposed to be a --hold build that
    # touched nothing.
    #
    # Guarding on DOCKER_BUILD rather than on --hold on purpose: the flag has to be threaded through
    # correctly to help, and this must hold even when it is not.  Stopping a node is never the right
    # thing to do from inside a build.
    if [[ "$DOCKER_BUILD" = "1" ]]; then
        echo "  (inside the build container -- not stopping anything)"
        node_stopped=1
        return 0
    fi
    # A LIVE INSTALL MAY ONLY TOUCH A GENERATION THAT HAS EXECUTED NOTHING.  Binaries land in the
    # current generation directory (see gen_dest below), so on a chain WITH history that would
    # rewrite the binaries that produced the existing blocks -- and a node replaying that history
    # afterwards would execute the old blocks with the new code.  That is the unreplayable-history
    # hazard the generation layout exists to end, so it is refused rather than merely warned about.
    #
    # A fresh home (no application.db -- init.sh just made it) has no history to invalidate, which
    # is what keeps the ordinary build-and-install loop working.
    if [[ -d "$QADENAHOME/data/application.db" ]]; then
        echo "Error: this chain has history; installing binaries would rewrite the generation that"
        echo "       produced it, and a node replaying those blocks would then execute them with"
        echo "       different code.  Schedule the change instead:"
        echo "           install_release.sh <archive> --stage-upgrade v<version>"
        echo "       (or build with --hold, which writes only versioned names), or wipe the chain"
        echo "       with buildscripts/init.sh if this is a throwaway node."
        exit 1
    fi
    echo "Stopping the node before installing binaries (a running binary cannot be replaced)"
    "$qadenascripts/stop_qadena.sh" --all > /dev/null 2>&1
    local alive
    alive=$(( $(count_procs qadenad) + $(count_procs qadenad_enclave) \
              + $(count_procs signer_enclave) + $(count_procs ego-host) + $(count_procs cosmovisor) ))
    if [[ $alive -ne 0 ]]; then
        echo "Error: $alive qadena process(es) still running after stop_qadena.sh --all."
        echo "       Refusing to install over them -- the copy would fail silently and you would be"
        echo "       left running the old binary while this script reported success."
        exit 1
    fi
    node_stopped=1
    echo "Node stopped.  It is NOT restarted by this script -- start it when you are ready."
}

# install_binary <src> <dst> -- a cp whose failure is fatal.
install_binary() {
    if ! cp "$1" "$2"; then
        echo "Error: failed to install $2 (from $1)"
        exit 1
    fi
}

# WHERE A LIVE BINARY GOES: the current generation's bin, never $qadenabin directly.  $qadenabin
# holds symlinks into this directory plus the versioned real copies, so writing here is what makes
# `qadenad` on this node mean the new build.  Versioned names (qadenad_enclave.<meas>, ...) stay in
# $qadenabin as REAL files -- the enclave handover and the identity tooling read them by name.
gen_dest() {
    local d
    d=$(cosmovisor_gen_bin)
    if [[ ! -d "$d" ]]; then
        echo "Error: $d does not exist -- this node has no cosmovisor generation to install into." >&2
        echo "       Create one with buildscripts/init.sh, or migrate a flat home with" >&2
        echo "       scripts/cosmovisor_setup.sh --migrate" >&2
        exit 1
    fi
    print -r -- "$d"
}

if [[ $install_enclave -eq 1 ]]; then
    echo "Installing enclave"
    [[ $hold -eq 0 ]] && ensure_stopped_for_binaries
    enclave_path="$qadenabuild/cmd/qadenad_enclave"
    # check if reproducible_build_unique_id.txt exists and $enclave_path/qadenad_enclave
    if [[ -f "$enclave_path/reproducible_build_unique_id.txt" ]]; then
        unique_id=$(cat "$enclave_path/reproducible_build_unique_id.txt")
    else
        unique_id=$(cat "$enclave_path/test_unique_id.txt")
    fi
    install_binary "$enclave_path/qadenad_enclave" "$qadenabin/qadenad_enclave.$unique_id"
    if [[ $hold -eq 1 ]]; then
        echo "  held back: staged as qadenad_enclave.$unique_id; the live binary is unchanged"
        echo "  deploy it as a governance plan (registration, promotion and the attested"
        echo "  handover all happen there): build.sh --release, commit, then roll the fleet."
    else
        install_binary "$enclave_path/qadenad_enclave" "$(gen_dest)/qadenad_enclave"
        cosmovisor_relink
    fi
fi

if [[ $install_signer_enclave -eq 1 ]]; then
    echo "Installing signer enclave"
    [[ $hold -eq 0 ]] && ensure_stopped_for_binaries
    signer_enclave_path="$qadenabuild/cmd/signer_enclave"
    # check if reproducible_build_unique_id.txt exists and $enclave_path/qadenad_enclave
    if [[ -f "$signer_enclave_path/reproducible_build_unique_id.txt" ]]; then
        unique_id=$(cat "$signer_enclave_path/reproducible_build_unique_id.txt")
    else
        unique_id=$(cat "$signer_enclave_path/test_unique_id.txt")
    fi
    install_binary "$signer_enclave_path/signer_enclave" "$qadenabin/signer_enclave.$unique_id"
    if [[ $hold -eq 1 ]]; then
        echo "  held back: staged as signer_enclave.$unique_id; the live binary is unchanged"
    else
        install_binary "$signer_enclave_path/signer_enclave" "$(gen_dest)/signer_enclave"
        cosmovisor_relink
    fi
fi

if [[ $install_chain -eq 1 ]]; then
    echo "Installing chain"
    [[ $hold -eq 0 ]] && ensure_stopped_for_binaries
    chain_path="$qadenabuild/cmd/qadenad"
    VERSION_FILE="$chain_path/version.txt"
    VERSION=$(cat "$VERSION_FILE")
    install_binary "$chain_path/qadenad" "$qadenabin/qadenad.$VERSION"
    if [[ $hold -eq 1 ]]; then
        echo "  held back: staged as qadenad.$VERSION; the live binary is unchanged"
    else
        install_binary "$chain_path/qadenad" "$(gen_dest)/qadenad"
        cosmovisor_relink
    fi

    # THE LIBRARIES ARE PART OF "THE LIVE BINARY", and this cp used to sit OUTSIDE the --hold guard
    # above -- so a --hold build, whose entire promise is that it touches nothing the running node
    # is using, overwrote libwasmvm underneath it.
    #
    # WHY THAT IS FATAL RATHER THAN UNTIDY.  qadenad links libwasmvm at LOAD time, so a running node
    # has it mapped r-xp for the life of the process.  install_binary is a plain `cp`: it writes new
    # bytes into the SAME INODE, and those page-cache pages back the live mapping.  Any page the
    # process has not faulted in yet then arrives from the NEW build, and the node executes
    # instructions from a different binary at addresses computed for the old one.  The result is a
    # SIGSEGV with no Go stack trace (the fault is in native code) and no OOM record (nothing was
    # ever out of memory) -- which is exactly what made it so hard to place.
    #
    # M1 died this way twice: 2026-08-24 20:27 and 2026-08-25 20:41, rc 139 both times, both during
    # a build, while all 60 other node exits in those logs were ordinary rc 1 stops.  Confirmed by
    # /proc/<pid>/maps showing the running qadenad mapped r-xp to the overwritten inode with no
    # "(deleted)" marker -- i.e. to the file the build had just rewritten under it.
    #
    # So under --hold the libraries are STAGED beside the versioned binary they belong to, never
    # written over the live ones.  The cutover installs them with the node stopped:
    # install_release.sh ships libwasmvm in the package and calls ensure_stopped_for_binaries first,
    # which is the only safe moment to replace a mapped library.
    if [[ $hold -eq 1 ]]; then
        for so in $qadenabuild/vendor/github.com/CosmWasm/wasmvm/v2/internal/api/*.so; do
            [[ -e "$so" ]] || continue
            cp "$so" "$qadenabin/$(basename $so).$VERSION" || {
                echo "Error: failed to stage $(basename $so).$VERSION"; exit 1; }
        done
        echo "  held back: libwasmvm staged as *.so.$VERSION; the live libraries are unchanged"
    else
        # BESIDE THE BINARY THAT LOADS THEM.  qadenad links with -Wl,-rpath,$ORIGIN, so each
        # generation resolves its own libwasmvm; putting these in $qadenabin instead would make
        # every generation load whichever copy happened to be there.
        cp $qadenabuild/vendor/github.com/CosmWasm/wasmvm/v2/internal/api/*.so "$(gen_dest)/"
        cosmovisor_relink
    fi
fi

if [[ $install_scripts -eq 1 ]]; then
    echo "Installing scripts"
    if [[ ! -d "$QADENAHOME/scripts" ]] ; then
        mkdir -p "$QADENAHOME/scripts"
    fi
    cp $qadenascripts/* "$QADENAHOME/scripts/"
    cp $qadenabuild/config.yml "$QADENAHOME/config"
    cp $qadenabuild/cmd/qadenad_enclave/public.pem "$QADENAHOME/config/public.pem"
fi

if [[ $install_testscripts -eq 1 ]]; then
    echo "Installing testscripts and test_data"
    if [[ ! -d "$QADENAHOME/testscripts" ]] ; then
        mkdir -p "$QADENAHOME/testscripts"
    fi
    if [[ ! -d "$QADENAHOME/test_data" ]] ; then
        mkdir -p "$QADENAHOME/test_data"
    fi
    cp $qadenatestscripts/* "$QADENAHOME/testscripts/"
    cp $qadenabuild/test_data/* "$QADENAHOME/test_data/"
fi

if [[ $install_provider_scripts -eq 1 ]]; then
    echo "Installing provider scripts"
    if [[ ! -d "$QADENAHOME/provider_scripts" ]] ; then
        mkdir -p "$QADENAHOME/provider_scripts"
    fi
    cp -r $qadenaproviderscripts/* "$QADENAHOME/provider_scripts/"
    if [[ ! -d "$QADENAHOME/veritas_scripts" ]] ; then
        mkdir -p "$QADENAHOME/veritas_scripts"
    fi
    cp $veritasscripts/* "$QADENAHOME/veritas_scripts/"
fi

echo "Install done."    