#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"


# Root only when an ego enclave is actually in play: SGX hardware AND a signed binary.
needs_root_if_real_enclave "stop_qadena.sh" "$qadenabin/qadenad_enclave"

# NOT SHORT-CIRCUITED WHEN SYSTEMD OWNS THE NODE.  "Nothing is running" is not the same as
# "nothing will run": an installed unit with Restart=on-failure can bring the node back seconds
# after this script would otherwise have declared success.  So when the unit is present we fall
# through and stop the UNIT below; only an unmanaged node can exit here.
if ! qadena_systemd_managed && ! is_qadena_running; then
    echo "stop_qadena.sh: Good!  Qadena is no longer running."
    exit 0
fi

# get argument "--enclave-only"
stop_enclave=0
stop_qadena=0
stop_signer_enclave=0
enclaves_only=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --enclave)
      stop_enclave=1
      shift
      ;;
    --chain)
      stop_qadena=1
      shift
      ;;
    --init-enclave)
      # The delayed_init_enclave.sh process this stopped no longer exists (init runs inside
      # qadenad since the enclave-selfstart change).  Accepted and ignored so older callers and
      # muscle memory keep working.
      shift
      ;;
    --signer-enclave)
      stop_signer_enclave=1
      shift
      ;;
    --all)
      stop_enclave=1
      stop_qadena=1
      stop_signer_enclave=1
      shift
      ;;
    --enclaves-only)
      # For cosmovisor_preupgrade.sh, which runs BETWEEN the old qadenad's halt and the binary
      # swap: the chain process is already gone (the halt), but rotatelogs is still the live log
      # pipe of the run.sh | rotatelogs pipeline that cosmovisor is running INSIDE.  Killing it
      # here would sever the node's own logging mid-upgrade -- so this mode stops both enclaves,
      # skips the chain block, skips rotatelogs, and skips the final is_qadena_running check
      # (which would count the healthy cosmovisor pipeline as a failure to stop).
      stop_enclave=1
      stop_signer_enclave=1
      enclaves_only=1
      shift
      ;;
    --help)
      echo "stop_qadena.sh:  Usage: stop_qadena.sh [--enclave] [--chain] [--signer-enclave] [--enclaves-only]"
      exit 0
      ;;
    *)
      echo "stop_qadena.sh:  Unknown option: $1"
      exit 1
      ;;
  esac
done

if [[ $stop_qadena -eq 0 && $stop_enclave -eq 0 && $stop_signer_enclave -eq 0 ]] ; then
    # assume all
    stop_qadena=1
    stop_enclave=1
    stop_signer_enclave=1
fi


# STOP THE UNIT FIRST, or every kill below races Restart=on-failure and the node comes back five
# seconds later looking like it never stopped.  systemd's KillMode=control-group SIGTERMs the whole
# cgroup -- qadenad, both enclaves and rotatelogs -- so the per-process work after this is
# belt-and-braces for anything started outside the unit.
#
# NEVER FOR --enclaves-only.  That mode exists for cosmovisor_preupgrade.sh, which runs INSIDE the
# unit at an upgrade height: stopping the unit from within it would tear down the very upgrade it
# was invoked to perform.  Same reason run.sh's post-exit mop-up uses --enclaves-only.
if qadena_systemd_managed && [[ $enclaves_only -eq 0 ]]; then
    echo "stop_qadena.sh: systemd unit present -- stopping qadena.service"
    sudo systemctl stop qadena || echo "stop_qadena.sh: WARNING: systemctl stop qadena failed; continuing with direct kills"
fi

echo "stop_qadena.sh: -----------"
echo "stop_qadena.sh: STOP QADENA"
echo "stop_qadena.sh: -----------"

stop_failed=0

# THE RESPAWN SUPERVISORS ARE GONE.  This script used to `pkill -KILL` the run_enclave.sh /
# run_signerenclave.sh `while true` loops FIRST, unconditionally, because killing an enclave while
# its supervisor lived just produced another one inside the verification window (one such loop
# survived four stop attempts across an hour).  Since the enclave-selfstart change the enclaves
# are children of qadenad with no respawn loop anywhere, so there is no supervisor to race --
# what remains below is plain process kills.
#
# ORDER STILL MATTERS, for a different reason: `pkill -f "qadenad"` also matches qadenad_ENCLAVE
# (substring), so the chain block below takes the enclave down with the chain -- which is fine,
# and the dedicated blocks after it mop up whatever form is left.

if [[ $stop_qadena -eq 1 ]] ; then
    echo "stop_qadena.sh: Stopping Qadena"
    # THE COSMOVISOR PARENT FIRST, when there is one.  `pkill -f "qadenad"` matches the CHILD (its
    # argv carries .../cosmovisor/current/bin/qadenad) but not the parent, whose argv is
    # `cosmovisor run start`.  Killed child-first, cosmovisor merely observes an exit and exits
    # after it -- fine in practice, but nothing verified it; parent-first is deterministic, and a
    # cosmovisor mid-upgrade-swap must not be left to finish the swap against a node we are
    # stopping.  Bracket-classed so this ssh-able command never matches itself.
    pkill -INT -f "[c]osmovisor run" 2>/dev/null
    pkill -INT -f "qadenad"

    # check if qadenad is dead after 2 seconds
    sleep 2
    if pgrep -f "qadenad" > /dev/null || pgrep -f "[c]osmovisor run" > /dev/null ; then
        echo "stop_qadena.sh: qadenad did not exit on SIGINT, escalating to SIGKILL"
        pkill -9 -f "[c]osmovisor run" 2>/dev/null
        pkill -9 -f "qadenad"
        sleep 1
        if pgrep -f "qadenad" > /dev/null || pgrep -f "[c]osmovisor run" > /dev/null ; then
            echo "stop_qadena.sh: Error: qadenad is STILL running after SIGKILL"
            stop_failed=1
        fi
    fi
    # NOT `exit 1` here.  Exiting mid-script leaves the enclave, init-enclave and signer-enclave
    # blocks below unrun, which is how a supervisor outlived the script meant to kill it.  The
    # failure is remembered and reported at the end, after everything else has been stopped.
fi

if [[ $stop_enclave -eq 1 ]] ; then
    echo "stop_qadena.sh: Stopping Qadena Enclave"

    # FIRST CHOICE: THE RECORDED PROCESS GROUP.  run_enclave_standalone.sh starts the enclave as the
    # leader of a new process group and writes the pgid here, so the launcher and the ego-host it
    # forks can be signalled as ONE unit -- no argv matching, nothing to miss.  This is the same
    # discipline x/qadena/keeper/enclave_supervisor.go applies to the enclaves qadenad spawns.
    #
    # Enclaves started any OTHER way -- as children of qadenad, or by upgrade_enclave.sh's direct
    # execs -- write no such file, so the pattern kills below remain the general path and run
    # regardless.  This block is an addition to them, not a replacement.
    enclave_pgid=$(cat "$qadena_enclave_pgidfile" 2>/dev/null)
    if [[ -n $enclave_pgid ]] ; then
        # The bracket class keeps the `ps | awk` inside process_group_members from matching itself,
        # exactly as it does for pgrep.
        if process_group_members "$enclave_pgid" "qadenad_encla[v]e" > /dev/null ; then
            echo "stop_qadena.sh: signalling enclave process group $enclave_pgid"
            kill -INT -- -$enclave_pgid 2>/dev/null
            for i in {1..60}; do
                process_group_members "$enclave_pgid" "qadenad_encla[v]e" > /dev/null || break
                sleep 1
            done
            if process_group_members "$enclave_pgid" "qadenad_encla[v]e" > /dev/null ; then
                echo "stop_qadena.sh: process group $enclave_pgid did not exit on SIGINT after 60s, escalating to SIGKILL"
                kill -KILL -- -$enclave_pgid 2>/dev/null
                sleep 2
            fi
        else
            # Left by a run that was killed outright or a machine that lost power.  Say so rather
            # than silently deleting it: a stale file here is the only evidence of an unclean stop.
            echo "stop_qadena.sh: stale enclave pgid $enclave_pgid (no enclave in that group), ignoring"
        fi
        rm -f "$qadena_enclave_pgidfile" 2>/dev/null
    fi

    # BOTH forms are attempted, deliberately.  Which one is running depends on how the enclave was
    # STARTED, not on what is installed now -- a rebuild between start and stop would otherwise
    # strand a live enclave that this script believes it killed.  pkill on an absent pattern is a
    # harmless no-op, so trying both is strictly safer than choosing.
    if use_real_enclave "$qadenabin/qadenad_enclave" ; then
      pkill -INT -f "ego-host.*qadenad_enclave"
    fi
    pkill -INT -f "qadenad_enclave"

    # SIGNALLING IS NOT STOPPING, and for an SGX enclave the gap is tens of seconds.
    #
    # `ego run` is a launcher that forks /opt/ego/bin/ego-host, and the enclave inside unwinds
    # slowly: the SOCKET disappears almost at once while the process pair lives on.  This block
    # used to send SIGINT and return, so the script could report a stopped enclave that was still
    # running -- the same shape as the process-group problem the in-process supervisor had, where
    # signalling the launcher left the grandchild alive.
    #
    # That is not cosmetic here.  add_full_node.sh --stop-for-funding stops the enclave and exits;
    # the resume run starts a new one, and the new enclave UNLINKS the "stale" socket before
    # binding.  If the old one is still dying, the two overlap: a client's readiness probe reaches
    # the OLD enclave (loaded, answers in milliseconds) and its next call dies with
    #     rpc error: code = Unavailable desc = error reading from server: EOF
    # because the socket underneath it has been replaced.  Measured on real SGX: still present 20s
    # after the stop, gone by 80s.
    #
    # So wait for it, and escalate rather than wait forever -- exactly what the chain block above
    # already does with its SIGINT -> SIGKILL.
    for i in {1..60}; do
        pgrep -f "qadenad_encla[v]e" > /dev/null 2>&1 || break
        sleep 1
    done
    if pgrep -f "qadenad_encla[v]e" > /dev/null 2>&1 ; then
        echo "stop_qadena.sh: the enclave did not exit on SIGINT after 60s, escalating to SIGKILL"
        if use_real_enclave "$qadenabin/qadenad_enclave" ; then
          pkill -KILL -f "ego-host.*qadenad_enclave"
        fi
        pkill -KILL -f "qadenad_enclave"
        sleep 2
    fi
    if pgrep -f "qadenad_encla[v]e" > /dev/null 2>&1 ; then
        echo "stop_qadena.sh: Error: the enclave is STILL running after SIGKILL"
        pgrep -af "qadenad_encla[v]e" | sed "s/^/    /"
        stop_failed=1
    fi
fi

if [[ $stop_signer_enclave -eq 1 ]] ; then
    echo "stop_qadena.sh: Stopping Qadena Signer Enclave"
    # same reasoning as above; gated on the signer binary, which is built independently
    if use_real_enclave "$qadenabin/signer_enclave" ; then
      pkill -KILL -f "ego-host.*signer_enclave"
    fi
    pkill -INT -f "signer_enclave"
fi

# stop rotatelogs
# if rotatelogs is running, stop it

#detect if rotatelogs is running
if [[ $enclaves_only -eq 0 ]]; then
    pgrep -f "rotatelogs.*qadena" > /dev/null
    if [[ $? -eq 0 ]]; then
        echo "stop_qadena.sh: Stopping rotatelogs"
        pkill -f "rotatelogs.*qadena"
    fi

    sleep 5
    if is_qadena_running; then
        echo "stop_qadena.sh: Error: Qadena is still running"
        exit 1
    fi
else
    # --enclaves-only: rotatelogs is the caller's live log pipe, and is_qadena_running would count
    # the cosmovisor pipeline this hook is running inside.  Verify only what this mode stopped.
    sleep 2
    if pgrep -x qadenad_enclave > /dev/null || pgrep -x signer_enclave > /dev/null || pgrep -f "[e]go-host" > /dev/null ; then
        echo "stop_qadena.sh: Error: an enclave is still running after --enclaves-only"
        stop_failed=1
    fi
fi

# REMOVE THE ENCLAVE'S UNIX SOCKET, because a leftover one can make the NEXT start fail in a way
# that names neither the file nor the reason.
#
# /tmp is sticky (1777), so a socket left by a run as another user -- root, typically, after the node
# was started with sudo -- cannot be unlinked by the login user.  The enclave then fails to bind with
# "address already in use" and exits, which now takes the whole node down with it.
# (cmd/qadenad_enclave/enclave.go reports this when it hits it; removing the socket here means it
# usually does not have to.)
#
# Best effort: we are the ones who just stopped the enclave, so if we cannot remove it, say so and
# name the command that will -- do not fail the stop over it.
for sock in /tmp/qadena_*.sock ; do
    [[ -e $sock ]] || continue
    if ! rm -f "$sock" 2>/dev/null; then
        # `stat -c` is GNU, `stat -f` is BSD/macOS; try both rather than print "?" on a Mac.
        owner=$(stat -c %U "$sock" 2>/dev/null || stat -f %Su "$sock" 2>/dev/null)
        echo "stop_qadena.sh: WARNING: could not remove $sock (owned by ${owner:-?}, /tmp is sticky)"
        echo "stop_qadena.sh:          the next start will fail to bind it.  Remove it with:"
        echo "stop_qadena.sh:              sudo rm -f $sock"
    fi
done

# A qadenad that survived SIGKILL above is still a failure, even though nothing is running under the
# names is_qadena_running looks for.  Reported here rather than by an early exit, so everything got
# stopped first.
exit $stop_failed