#!/bin/zsh

# Runs a Qadena node.  Since the enclave-selfstart change this is a thin wrapper: `qadenad start`
# itself spawns and supervises both enclave processes (x/qadena/keeper/enclave_supervisor.go) and
# initializes a fresh chain's enclave from BeginBlock (enclave_init_dispatch.go).  What remains
# here is host-side preparation that the chain binary should not do:
#
#   - the SGX device / root preflight, loudly and BEFORE output disappears into rotatelogs
#   - the enclave-upgrade check (swaps binaries; must precede any process starting)
#   - the DCAP/PCCS attestation sidecar for real enclaves (managing docker is host provisioning)
#
# The five-script choreography this replaced -- run_enclave.sh, run_realenclave.sh,
# run_signerenclave.sh, run_realsignerenclave.sh, delayed_init_enclave.sh, init_enclave.sh, each
# started in strict order with poll loops between -- is gone.  The enclave death policy changed
# with it, deliberately: a spawned enclave that exits takes the node down with a named error
# instead of being silently respawned, so the process supervisor (systemd Restart=on-failure)
# restarts the node and the startup reconcile path recovers.  See the supervisor's file comment
# for why the respawn loops had to go.

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

# Root is needed only when we will actually run an ego enclave -- i.e. SGX hardware AND a signed
# binary.  qadenad re-checks this in its spawn preflight with the same remedies, but failing HERE
# keeps the message on the operator's terminal instead of inside the log pipe.
warn_if_sgx_binary_missing "run.sh" "$qadenabin/qadenad_enclave"
needs_root_if_real_enclave "run.sh" "$qadenabin/qadenad_enclave"

EXTERNAL_ENCLAVE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --external-enclave)
      # Forwarded to qadenad: dial an externally started enclave (run_enclave_standalone.sh,
      # typically under a debugger) instead of spawning one.
      EXTERNAL_ENCLAVE="--external-enclave"
      shift
      ;;
    --help)
      echo "run.sh:  Usage: run.sh [--external-enclave]"
      echo "run.sh:    --external-enclave   do not spawn enclaves; dial one started separately"
      echo "run.sh:                         (see run_enclave_standalone.sh)"
      exit 0
      ;;
    *)
      echo "run.sh:  Unknown option: $1"
      exit 1
      ;;
  esac
done

# Fail before anything starts: a node with no external_address cannot register itself, and
# qadenad start would refuse a few seconds later anyway -- this keeps the message here.
EXT_ADDR=`$qadenascripts/get_external_address.sh`
if [[ $EXT_ADDR == "" ]] ; then
    echo "run.sh:  Error, config.toml's external_address is not defined.  Try running init.sh"
    exit 1
fi

$qadenascripts/check_upgrade_enclave.sh
RET=$?
if [ $RET -ne 0 ] ; then
    echo "run.sh:  Error: qadenad_enclave has an upgrade, but it failed when trying to upgrade."
    if [ $RET -eq 5 ] ; then
        echo "run.sh:  Error: qadenad_enclave upgrade failed because the current enclave has not been registered with the chain.  Did you submit a proposal?"
        exit 5
    fi
    exit $RET
fi

# Attestation must be available before qadenad spawns a REAL enclave.  Skipped entirely for a
# debug build; skipped for --external-enclave because whoever started that enclave prepared it.
if [[ -z $EXTERNAL_ENCLAVE ]] && use_real_enclave "$qadenabin/qadenad_enclave" ; then
    $qadenascripts/ensure_sgx_attestation.sh || exit 1
fi

echo "run.sh: ------------"
echo "run.sh: START QADENA"
echo "run.sh: ------------"

# Foreground: qadenad is now the whole node -- it spawns the enclaves, and this script has
# nothing to monitor.  Note what is GONE from this line versus the old one: --enclave-addr and
# the id flags were inert (the unix-domain-socket branch never read them), and --log-level was a
# lossy re-derivation of the config.toml value qadenad reads natively.
#
# EVERY NODE LAUNCHES THROUGH COSMOVISOR -- there is no other mode.  The ~30 scripts that start
# and stop nodes still never mention it: they call start_qadena.sh, and this is the one place that
# knows how a node is launched.
#
# The check_upgrade_enclave.sh preflight above runs in BOTH branches on purpose: cosmovisor's
# post-swap restart bypasses run.sh entirely, so if the at-height handoff failed, the next manual
# restart through here is what retries it.  Do not "clean this up" by moving the detect above it.
# EVERY NODE LAUNCHES THROUGH COSMOVISOR.  There is no direct-launch fallback: a node whose tree
# is missing has lost the thing that makes its history replayable, and starting it anyway is how
# that gets discovered weeks later on a joiner.  Fail here, with the command that fixes it.
cosmovisor_require "run.sh" || exit 1

if [[ -n $EXTERNAL_ENCLAVE ]] ; then
    # The at-height hook tears down every enclave it finds, so an operator's debugger-attached
    # enclave would be collateral.  Attach to the enclave the node spawns instead.
    echo "run.sh:  Error: --external-enclave is not supported (every node is cosmovisor-managed;"
    echo "run.sh:         the upgrade hook would tear down an externally started enclave)."
    exit 1
fi

echo "run.sh: cosmovisor (current -> $(readlink $QADENAHOME/cosmovisor/current))"

# ---------------------------------------------------------------------------------------------
# THE KEYRING PASSPHRASE, WHEN AND ONLY WHEN A HUMAN STARTED THIS.
#
# enclave_selfstart's dispatch reads the pioneer key out of the node's own keyring (backend from
# client.toml) to hand it to the enclave in MsgInitEnclave.  With the `file` backend that read
# prompts, and qadenad prompts on ITS OWN STDIN -- so answering it means BEING the feed, exactly
# as 1st_node_bringup.sh is for a remote bring-up.  One answer is not enough: the number of
# prompts is not fixed, which is why that script streams the passphrase rather than echoing it
# once.
#
# WHY -t 0 IS THE WHOLE TEST.  The three ways this script starts have three different stdins, and
# only one of them wants a prompt:
#
#   a human in a terminal   -> tty      -> ask
#   1st/nth_node_bringup.sh -> pipe     -> already being fed; asking would consume its first line
#   systemd                 -> /dev/null-> cannot be answered at all (the unit has no
#                                          StandardInput, which is why the fleet does the first
#                                          start outside systemd)
#
# So no flag, no env var, and no way for this to fire on the fleet.
# ---------------------------------------------------------------------------------------------

# The marker, the "can a human answer" test and the "is it still owed" test all live in
# setup_env.sh, shared with start_qadena.sh and restart_qadena.sh so the three cannot disagree
# about when the passphrase is needed.  Read the commentary there before changing this.

# ASK THE CHAIN, THE WAY THE BRING-UP DOES.  JarRegulator is what MaybeDispatchInitEnclave itself
# gates on; genesis leaves the list empty and only the enclave can fill it (the row carries an
# attestation report), so a non-empty answer is proof rather than a hint.  The log is not usable
# here -- a successful dispatch has three possible phrasings and has been observed writing none.
_rs_jar_count() {
    "$qadenabin/qadenad" query qadena list-jar-regulator --home "$QADENAHOME" --output json 2>/dev/null \
        | sed -n '/^{/,$p' | jq -r '(.jarRegulator // []) | length' 2>/dev/null
}

if qadena_can_prompt && qadena_needs_first_start_passphrase ; then
    echo "run.sh: this node's keyring is the 'file' backend and it is not recorded as registered yet."
    echo "run.sh: the passphrase is needed ONCE, to hand the pioneer key to the enclave."
    # ENTER SKIPS, ALWAYS.  A missing or deleted marker on an already-registered node is a
    # nuisance, not a dead end -- and the watcher below writes the marker either way, so it is a
    # one-time nuisance.  An answer that cannot be declined would turn a stale marker into a
    # node that will not start.
    # CHECK IT BEFORE TRUSTING IT.  An unchecked answer is worse here than no answer: the node
    # starts, runs, serves RPC and produces blocks, and the only sign that the passphrase was
    # wrong is an enclave that never registers -- the exact silent failure start_qadena.sh now
    # refuses to create.  A typo should cost a retry, not a debugging session.
    #
    # OPEN THE KEY THE DISPATCH WILL OPEN, not just any key.  runInitEnclaveDispatch reads the key
    # named by the MONIKER (enclave_selfstart.go: GetAddressByName(clientCtx, moniker, ...)), so
    # that is what gets tested.  Checking some other key would pass while the one that matters
    # is missing.
    _rs_moniker=$(sed -nE 's/^moniker[[:space:]]*=[[:space:]]*"?([^"]*)"?.*/\1/p' \
        "$QADENAHOME/config/config.toml" 2>/dev/null | head -1)
    if [[ -z "$_rs_moniker" ]] ; then
        echo "run.sh:  Error: config.toml has no moniker -- the enclave registers under that name."
        exit 1
    fi

    _rs_ok=0
    _rs_skipped=0
    for _rs_try in 1 2 3 ; do
        print -n "run.sh: keyring passphrase for '$_rs_moniker' (Enter to skip if already registered): "
        read -rs _rs_pass
        print
        # ENTER SKIPS, ALWAYS.  A missing or deleted marker on an already-registered node is a
        # nuisance, not a dead end -- and the watcher below writes the marker either way, so it
        # is a one-time nuisance.  An answer that cannot be declined would turn a stale marker
        # into a node that will not start.
        if [[ -z "$_rs_pass" ]] ; then
            echo "run.sh: skipped -- starting without a passphrase feed"
            _rs_skipped=1
            break
        fi

        # BUILTINS ONLY, AND MORE PROMPTS THAN IT ASKS FOR.  `repeat`/`print` are zsh builtins, so
        # the passphrase never becomes an argument visible in `ps` -- the same reason setup_env.sh
        # feeds it this way rather than with `yes`.  The count is generous because the number of
        # prompts a command issues is not fixed.
        # STDERR TO A FILE, NOT TO $( ).  $pipestatus describes the LAST PIPELINE THIS SHELL RAN,
        # and a pipeline inside $( ) is run by the substitution's own shell -- so reading it after
        # `_e=$( a | b )` gives the status of the ASSIGNMENT, which is an empty array here.  zsh
        # then evaluates `(( _rs_rc == 0 ))` on an empty string as arithmetic ZERO, i.e. SUCCESS:
        # every wrong passphrase was accepted, the feed was armed with it and the node started.
        # Exactly the silent-unregistered node this check exists to prevent.
        #
        # Run the pipeline directly and read $pipestatus on the very next line, where it is valid.
        _rs_errfile=$(mktemp "${TMPDIR:-/tmp}/.qadena-run-err.XXXXXX") || {
            echo "run.sh:  Error: could not create a temporary file"; exit 1 }
        { repeat 8 print -r -- "$_rs_pass" } \
            | "$qadenabin/qadenad" keys show "$_rs_moniker" -a \
                  --keyring-backend "$QADENA_KEYRING_BACKEND" --home "$QADENAHOME" \
                  >/dev/null 2>"$_rs_errfile"
        _rs_rc=${pipestatus[2]}
        _rs_err=$(<"$_rs_errfile")
        rm -f "$_rs_errfile"

        if (( _rs_rc == 0 )) ; then
            _rs_ok=1
            echo "run.sh: passphrase accepted -- '$_rs_moniker' opened"
            break
        fi

        # WHICH FAILURE, because the exit code is 1 for both.  A wrong passphrase is a retry; a
        # missing key is not -- no number of attempts creates it, and the dispatch would fail
        # with "no key named <moniker> in the keyring" however the passphrase was typed.
        if [[ "$_rs_err" == *"passphrase"* ]] ; then
            echo "run.sh: that passphrase did not open the keyring (attempt $_rs_try of 3)"
        else
            echo "run.sh:  Error: could not read key '$_rs_moniker' from the keyring:"
            echo "run.sh:         ${_rs_err##*$'\n'}"
            echo "run.sh:         This is not a passphrase problem -- the enclave registers under"
            echo "run.sh:         the moniker, so that key has to exist.  Check 'qadenad keys list'."
            unset _rs_pass
            exit 1
        fi
        unset _rs_pass
    done

    if (( _rs_ok )) ; then
        # BECOME THE FEED, by replacing this script's stdin -- so the launch line below is
        # untouched and cosmovisor inherits it like any other stdin.
        #
        # BOUNDED.  When the window closes the pipe reaches EOF, which is what we want a late
        # read to get: an unbounded feed would leave the passphrase available on stdin for the
        # entire life of the node.  20 minutes is the bring-up scripts' figure and covers a
        # genesis start reaching height 2 on a slow box.
        exec < <(_end=$((SECONDS+1200)); while (( SECONDS < _end )); do print -r -- "$_rs_pass"; done)
        unset _rs_pass
        echo "run.sh: feeding the passphrase to the node's first start"
    elif (( ! _rs_skipped )) ; then
        # THREE WRONG ANSWERS IS A STOP, not a start.  Proceeding would build precisely the node
        # start_qadena.sh refuses to create: healthy-looking, unregistered, and silent about why.
        # An explicit Enter is different -- that is a deliberate choice, and it falls through.
        unset _rs_pass
        echo "run.sh:  Error: the passphrase did not open '$_rs_moniker' after 3 attempts -- not starting."
        echo "run.sh:         Starting anyway would give you a node that runs but never registers."
        exit 1
    fi
fi

# WRITE THE MARKER ONLY ONCE THE CHAIN SAYS SO.  Backgrounded because the node has to be up to
# answer, and this script is about to hand its foreground to cosmovisor.  It exits on its own:
# either the row appears, or the window closes and no marker is written -- which is the correct
# outcome for a node that never registered.
#
# Runs even when the prompt was skipped, so an already-registered node stops asking from now on.
if qadena_needs_first_start_passphrase ; then
    (
        _end=$((SECONDS+1800))
        while (( SECONDS < _end )) ; do
            sleep 20
            _n=$(_rs_jar_count)
            if [[ -n "$_n" && "$_n" != "0" ]] ; then
                # The passphrase is never needed again: enclave_selfstart reads the keyring at the
                # first init only, and every later block returns early once GetJarRegulator finds
                # the row (d.doneForGood).
                : > "$QADENA_REGISTERED_MARKER" 2>/dev/null && \
                    echo "run.sh: enclave is registered on chain -- recorded in $QADENA_REGISTERED_MARKER (no passphrase needed on future starts)"
                break
            fi
        done
    ) &
fi

    # A SWAP COSMOVISOR CANNOT PERFORM ITSELF.
    #
    # cosmovisor decides to upgrade by watching data/upgrade-info.json, but gates that decision on
    # `<current-binary> status` reporting a height >= the plan height.  That gate needs a LIVE RPC,
    # and there is one important case where it never gets one: a node REPLAYING history that halts
    # at the boundary.  It dies applying the plan's block before its RPC ever serves, so the gate
    # errors, cosmovisor treats the exit as an ordinary crash, and the next start replays into the
    # same panic.  That loop is permanent -- and it is exactly the genesis-joiner case cosmovisor
    # exists here to make work (observed on a joiner at height 486, 2026-08-26).
    #
    # x/upgrade writes upgrade-info.json ONLY when it actually halts for a plan, so the file's
    # presence plus a `current` that does not already point at that plan means: this node stopped
    # for an upgrade it has not performed.
    cosmovisor_pending_plan() {
        local f="$QADENAHOME/data/upgrade-info.json" plan cur
        [[ -f "$f" ]] || return 1
        plan=$(sed -n 's/.*"name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$f" | head -1)
        [[ -n "$plan" ]] || return 1
        cur=$(readlink "$QADENAHOME/cosmovisor/current")
        [[ "$cur" == *"upgrades/$plan" ]] && return 1     # already performed
        print -r -- "$plan"
    }

    cosmovisor_perform_swap() {   # plan
        local plan="$1"
        if [[ ! -x "$QADENAHOME/cosmovisor/upgrades/$plan/bin/qadenad" ]] ; then
            echo "run.sh:  Error: this node halted for upgrade '$plan' but nothing is staged at"
            echo "run.sh:         $QADENAHOME/cosmovisor/upgrades/$plan/bin -- it cannot start until"
            echo "run.sh:         that release is staged (install_release.sh --stage-upgrade $plan)."
            return 1
        fi
        echo "run.sh: this node halted for upgrade '$plan' and has not performed it -- resuming the swap"
        if [[ -x "$QADENAHOME/cosmovisor/cosmovisor_preupgrade.sh" ]] ; then
            "$QADENAHOME/cosmovisor/cosmovisor_preupgrade.sh" "$plan" || {
                echo "run.sh:  Error: the preupgrade hook failed for '$plan'; not swapping"
                return 1
            }
        fi
        ( cd "$QADENAHOME/cosmovisor" && rm -f current && ln -s "upgrades/$plan" current ) \
            || { echo "run.sh:  Error: could not repoint current at upgrades/$plan"; return 1 }
        echo "run.sh: current -> $(readlink $QADENAHOME/cosmovisor/current)"
        return 0
    }

    # THE LOOP EXISTS BECAUSE A HALT IS NOT A CRASH.  When a replaying node halts at the boundary,
    # cosmovisor exits and so would this script -- leaving a node that is DOWN for a reason it
    # could resolve by itself, waiting on a supervisor that may not exist (the fleet drives nodes
    # by script, not systemd).  Performing the owed swap and relaunching is what any supervisor
    # would do.  It TERMINATES: a swap repoints `current` at the plan, so the same plan is never
    # owed twice, and a swap that cannot be performed returns non-zero and exits.
    while : ; do
        _plan=$(cosmovisor_pending_plan) && { cosmovisor_perform_swap "$_plan" || exit 1 }

        DAEMON_NAME="${DAEMON_NAME:-qadenad}" \
        DAEMON_HOME="${DAEMON_HOME:-$QADENAHOME}" \
        DAEMON_RESTART_AFTER_UPGRADE="${DAEMON_RESTART_AFTER_UPGRADE:-true}" \
        DAEMON_ALLOW_DOWNLOAD_BINARIES="${DAEMON_ALLOW_DOWNLOAD_BINARIES:-false}" \
        UNSAFE_SKIP_BACKUP="${UNSAFE_SKIP_BACKUP:-true}" \
        COSMOVISOR_CUSTOM_PREUPGRADE="${COSMOVISOR_CUSTOM_PREUPGRADE:-cosmovisor_preupgrade.sh}" \
        "$qadenabin/cosmovisor" run start --json-rpc.api eth,txpool,personal,net,debug,web3 --api.enable=true --grpc.enable=true --grpc.address 0.0.0.0:9090 --home=$QADENAHOME
        RC=$?

        cosmovisor_pending_plan > /dev/null || break
        echo "run.sh: the node stopped for a scheduled upgrade it has not performed -- completing it and restarting"
    done


echo "run.sh: ------------"
echo "run.sh: QADENA ENDED (rc $RC)"
echo "run.sh: ------------"

# Belt and braces: a clean shutdown already took the spawned enclaves along (SIGINT forwarding in
# the supervisor), but a PANIC exits without running handlers and orphans them.  Harmless -- the
# next start would adopt the orphan -- but a stopped node should leave a stopped machine.
if [[ -z $EXTERNAL_ENCLAVE ]] ; then
    if is_qadena_running ; then
        # --enclaves-only, NOT --all: this runs as the unit's own ExecStart on its way out, and a
        # full stop would ask systemd to stop the service that is currently executing this line.
        # Reaping the orphaned enclaves is all that is wanted here anyway; systemd's
        # KillMode=control-group takes the rest of the cgroup.
        echo "run.sh: cleaning up enclave processes the node left behind"
        $qadenascripts/stop_qadena.sh --enclaves-only
    fi
fi

exit $RC
