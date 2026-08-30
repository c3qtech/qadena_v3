#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

# This script runs the enclave twice (--upgrade-mode, then the new binary) and had no privilege
# check at all, so on a machine whose devices are out of reach it failed inside ego rather than
# saying which groups to join.  The upgrade is the worst place to discover that: it stops the
# node and swaps the enclave binary first.
# judged after arg parsing would be better, but needs_root re-execs under sudo and must run
# before anything else -- so it checks the DEFAULT live name; an --old-bin/--new-bin caller on
# SGX hardware is expected to already hold the privileges (cosmovisor inherits the node's).
needs_root_if_real_enclave "upgrade_enclave.sh" "$qadenabin/qadenad_enclave"

FROM_ENCLAVE_UNIQUE_ID=""
OLD_BIN=""
NEW_BIN=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --from-enclave-unique-id)
      if [[ -n "$2" && "$2" != --* ]]; then
        FROM_ENCLAVE_UNIQUE_ID="$2"
        shift 2
      else
        echo "Error: --from-enclave-unique-id requires an unique-id argument"
        exit 1
      fi
      ;;
    # EXPLICIT BINARY PATHS, for callers that cannot use the default name resolution.
    # cosmovisor_preupgrade.sh is the one that matters: it runs BEFORE cosmovisor flips the
    # `current` symlink, so at that moment $qadenabin/qadenad_enclave still resolves to the OLD
    # build -- the default below would hand over from the old enclave TO the old enclave.  It
    # names the staged upgrades/<plan>/bin binary as --new-bin instead.  Defaults preserve the
    # historical behavior exactly.
    --old-bin)
      if [[ -n "$2" && "$2" != --* ]]; then OLD_BIN="$2"; shift 2
      else echo "Error: --old-bin requires a path"; exit 1; fi
      ;;
    --new-bin)
      if [[ -n "$2" && "$2" != --* ]]; then NEW_BIN="$2"; shift 2
      else echo "Error: --new-bin requires a path"; exit 1; fi
      ;;
    --help)
      echo "Usage: upgrade_enclave.sh --from-enclave-unique-id <unique-id> [--old-bin <path>] [--new-bin <path>]"
      exit 0
      ;;      
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

if [[ -z "$FROM_ENCLAVE_UNIQUE_ID" ]] ; then
    echo "Error: --from-enclave-unique-id requires an unique-id argument"
    exit 1
fi

[[ -n "$OLD_BIN" ]] || OLD_BIN="$qadenabin/qadenad_enclave.$FROM_ENCLAVE_UNIQUE_ID"
[[ -n "$NEW_BIN" ]] || NEW_BIN="$qadenabin/qadenad_enclave"
[[ -x "$OLD_BIN" ]] || { echo "Error: old enclave binary not executable: $OLD_BIN"; exit 1 }
[[ -x "$NEW_BIN" ]] || { echo "Error: new enclave binary not executable: $NEW_BIN"; exit 1 }

# run the old enclave
# The OLD and NEW enclaves are judged SEPARATELY, because they are separate binaries and can
# legitimately disagree mid-upgrade -- the old one signed and the new one debug, or the reverse.
#
# old_is_sgx is recorded rather than re-evaluated later: the kill at the end of this script must
# match whichever way this branch actually went.  Re-testing there could pick the other arm (the
# binary can be replaced underneath us) and leave the old enclave running.
if use_real_enclave "$OLD_BIN" ; then
    old_is_sgx=1
    ego run $OLD_BIN --realenclave --home=$QADENAHOME --chain-id=$CHAINID --upgrade-mode &
    pid=$!
else
    old_is_sgx=0
    $OLD_BIN --home=$QADENAHOME --chain-id=$CHAINID --upgrade-mode &
    pid=$!
fi

# Wait for the enclave's unix socket to answer.  The old probe here watched netstat for "50051",
# a TCP port nothing has bound since the enclave moved to /tmp/qadena_50051.sock -- it matched the
# socket PATH in the netstat output by accident.  Test the socket file directly.
IS_UP=0
for i in {90..1}
do
    if [ -S /tmp/qadena_50051.sock ] ; then
	echo "qadenad_enclave is up and running!"
	IS_UP=1
	break
    else
	echo "qadenad_enclave is not yet up, waiting...$i"
	sleep 1
    fi
done
if [ $IS_UP -ne 1 ] ; then
    echo "Could not run the qadenad_enclave"
    exit 1
fi

if use_real_enclave "$NEW_BIN" ; then
  ego run $NEW_BIN --realenclave --home=$QADENAHOME --chain-id=$CHAINID --upgrade-from-enclave-unique-id=$FROM_ENCLAVE_UNIQUE_ID
else
  $NEW_BIN --home=$QADENAHOME --chain-id=$CHAINID --upgrade-from-enclave-unique-id=$FROM_ENCLAVE_UNIQUE_ID
fi

RES=$?

# KILL THE OLD ENCLAVE BY PID, NOT BY PATTERN.
#
# `pkill -INT -f "$OLD_BIN"` MATCHED THIS SCRIPT ITSELF and SIGINTed it.  cosmovisor_preupgrade.sh
# invokes us as
#     upgrade_enclave.sh --from-enclave-unique-id unique061 --old-bin <...>/qadenad_enclave ...
# so $OLD_BIN is a substring of our OWN command line; pkill -f tests every process's full argv,
# found ours, and killed the shell before it reached `exit $RES` two lines below.  The handoff had
# already SUCCEEDED -- the params were ferried and enclave_params_<new>.json written with the keys
# intact -- and the script still exited 130 (128+SIGINT).  cosmovisor_preupgrade.sh read that as
# "the params handoff failed", refused the swap, and the node stayed down on the old binaries while
# systemd crash-looped it to StartLimitBurst.  A whole fleet sat halted at the plan height for three
# hours on a handoff that had worked.  Observed on M1, 2026-08-30, plan v1.1.29.
#
# The PID has been sitting in $pid since we started it; use it.  Same family as d74fb99b
# (stop_qadena.sh SIGINTing the build that called it) and the bracket-class rule in setup_env.sh.
if [[ $old_is_sgx -eq 1 ]] ; then
    # ego run spawns ego-host as a CHILD, so $pid is the wrapper and signalling it is not enough.
    # Bracket-classed so this pattern cannot match the command line that carried it here either.
    pkill -INT -f "/opt/ego/bin/ego-hos[t]"
else
    kill -INT "$pid" 2>/dev/null
fi

exit $RES

