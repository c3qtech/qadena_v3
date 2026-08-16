#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"


# Root only when an ego enclave is actually in play: SGX hardware AND a signed binary.
needs_root_if_real_enclave "stop_qadena.sh" "$qadenabin/qadenad_enclave"

if ! is_qadena_running; then
    echo "stop_qadena.sh: Good!  Qadena is no longer running."
    exit 0
fi

# get argument "--enclave-only"
stop_enclave=0
stop_qadena=0
stop_init_enclave=0
stop_signer_enclave=0

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
      stop_init_enclave=1
      shift
      ;;
    --signer-enclave)
      stop_signer_enclave=1
      shift
      ;;
    --all)
      stop_enclave=1
      stop_qadena=1
      stop_init_enclave=1
      stop_signer_enclave=1
      shift
      ;;
    --help)
      echo "stop_qadena.sh:  Usage: stop_qadena.sh [--enclave] [--chain] [--init-enclave] [--signer-enclave]"
      exit 0
      ;;      
    *)
      echo "stop_qadena.sh:  Unknown option: $1"
      exit 1
      ;;
  esac
done

if [[ $stop_qadena -eq 0 && $stop_enclave -eq 0 && $stop_init_enclave -eq 0 ]] ; then
    # assume all
    stop_qadena=1
    stop_enclave=1
    stop_init_enclave=1
    stop_signer_enclave=1
fi


echo "stop_qadena.sh: -----------"
echo "stop_qadena.sh: STOP QADENA"
echo "stop_qadena.sh: -----------"

stop_failed=0

# SUPERVISORS DIE FIRST.  run_enclave.sh and run_signerenclave.sh are `while true` respawn loops, so
# killing an enclave while its supervisor lives just produces another one -- inside the two-second
# window this script then uses to decide whether the kill worked.
#
# That produced a supervisor nothing could stop.  `pkill -f "qadenad"` also matches qadenad_ENCLAVE
# (substring), so the chain block below would kill the enclave, run_enclave.sh would restart it, the
# "still running" check would trip, and the script would exit 1 -- BEFORE reaching the enclave block
# that kills run_enclave.sh.  Every subsequent stop repeated it.  One survived four attempts across
# an hour, kept respawning a DEBUG enclave, and made is_qadena_running true forever; start_qadena.sh
# then reported "already running" and never launched the chain, so a --from-genesis run failed with
# "chain did not produce a block within 120s" and no mention of any of this.
#
# Unconditional, and before the flag checks: a stray supervisor is never wanted, whichever subset of
# components this invocation was asked to stop.
pkill -KILL -f "run_enclave.sh"
pkill -KILL -f "run_signerenclave.sh"

if [[ $stop_qadena -eq 1 ]] ; then
    echo "stop_qadena.sh: Stopping Qadena"
    pkill -INT -f "qadenad"

    # check if qadenad is dead after 2 seconds
    sleep 2
    if pgrep -f "qadenad" > /dev/null ; then
        echo "stop_qadena.sh: qadenad did not exit on SIGINT, escalating to SIGKILL"
        pkill -9 -f "qadenad"
        sleep 1
        if pgrep -f "qadenad" > /dev/null ; then
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
    # BOTH forms are attempted, deliberately.  Which one is running depends on how the enclave was
    # STARTED, not on what is installed now -- a rebuild between start and stop would otherwise
    # strand a live enclave that this script believes it killed.  pkill on an absent pattern is a
    # harmless no-op, so trying both is strictly safer than choosing.
    if use_real_enclave "$qadenabin/qadenad_enclave" ; then
      pkill -INT -f "ego-host.*qadenad_enclave"
    fi
    pkill -KILL -f "run_enclave.sh"
    pkill -INT -f "qadenad_enclave"
fi

if [[ $stop_init_enclave -eq 1 ]] ; then
    echo "stop_qadena.sh: Stopping Qadena Init Enclave"
    pkill -INT -f "delayed_init_enclave.sh"
fi

if [[ $stop_signer_enclave -eq 1 ]] ; then
    echo "stop_qadena.sh: Stopping Qadena Signer Enclave"
    # same reasoning as above; gated on the signer binary, which is built independently
    if use_real_enclave "$qadenabin/signer_enclave" ; then
      pkill -KILL -f "ego-host.*signer_enclave"
    fi
    pkill -KILL -f "run_signerenclave.sh"
    pkill -INT -f "signer_enclave"
fi

# stop rotatelogs
# if rotatelogs is running, stop it

#detect if rotatelogs is running
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

# REMOVE THE ENCLAVE'S UNIX SOCKET, because a leftover one can make the NEXT start fail in a way
# that names neither the file nor the reason.
#
# /tmp is sticky (1777), so a socket left by a run as another user -- root, typically, after the node
# was started with sudo -- cannot be unlinked by the login user.  The enclave then fails to bind with
# "address already in use", and run_enclave.sh retries forever against a condition that will never
# clear on its own.  (cmd/qadenad_enclave/enclave.go reports this when it hits it; removing the
# socket here means it usually does not have to.)
#
# Best effort: we are the ones who just stopped the enclave, so if we cannot remove it, say so and
# name the command that will -- do not fail the stop over it.
for sock in /tmp/qadena_*.sock ; do
    [[ -e $sock ]] || continue
    if ! rm -f "$sock" 2>/dev/null; then
        owner=$(stat -c %U "$sock" 2>/dev/null)
        echo "stop_qadena.sh: WARNING: could not remove $sock (owned by ${owner:-?}, /tmp is sticky)"
        echo "stop_qadena.sh:          the next start will fail to bind it.  Remove it with:"
        echo "stop_qadena.sh:              sudo rm -f $sock"
    fi
done

# A qadenad that survived SIGKILL above is still a failure, even though nothing is running under the
# names is_qadena_running looks for.  Reported here rather than by an early exit, so everything got
# stopped first.
exit $stop_failed