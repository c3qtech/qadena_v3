#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

# if REAL_ENCLAVE, check if running as root
if [[ $REAL_ENCLAVE -eq 1 ]]; then
    if [[ $(id -u) -ne 0 ]]; then
        echo "run.sh:  Error: qadenad_enclave must be run as root"
        exit 1
    fi
fi

# get argument "--sync-with-pioneer X"
SYNC_WITH_PIONEER=""
DEBUG=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --sync-with-pioneer)
      if [[ -n "$2" && "$2" != --* ]]; then
        SYNC_WITH_PIONEER="$2"
        shift 2
      else
        echo "run.sh:  Error: --sync-with-pioneer requires a node argument"
        exit 1
      fi
      ;;
    --no-qadenad-enclave)
      DEBUG="no_qadenad_enclave"
      shift
      ;;
    --help)
      echo "run.sh:  Usage: run.sh [--no-qadenad-enclave] [--sync-with-pioneer <node>]"
      exit 0
      ;;      
    *)
      echo "run.sh:  Unknown option: $1"
      exit 1
      ;;
  esac
done

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

PIDS=()
declare -A PROC_NAMES

if [[ $DEBUG != "no_qadenad_enclave" ]] ; then
        if [[ $REAL_ENCLAVE == 1 ]] ; then
            $qadenascripts/run_realenclave.sh &
            PIDS+=$!
            PROC_NAMES[$!]="run_realenclave.sh"
            echo "run.sh: enclave started by script, PID: $!"
        else
            $qadenascripts/run_enclave.sh &
            PIDS+=$!
            PROC_NAMES[$!]="run_enclave.sh"
            echo "run.sh: enclave started by script, PID: $!"
        fi
fi


IS_UP=0
for i in {90..1}
do
    if qadenad_alias enclave check-enclave ; then
        echo "run.sh: qadenad_enclave is up and running!"
        IS_UP=1
        break
    else
        echo "run.sh: qadenad_enclave is not yet up, waiting...$i"
        sleep 1
    fi
done
if [ $IS_UP -ne 1 ] ; then
    echo "run.sh: Could not run the qadenad_enclave"
    exit 1
fi

if [[ $DEBUG != "no_signer_enclave" ]] ; then
        if [[ $REAL_ENCLAVE == 1 ]] ; then
            $qadenascripts/run_realsignerenclave.sh &
            PIDS+=$!
            PROC_NAMES[$!]="run_realsignerenclave.sh"
            echo "run.sh: signer enclave started by script, PID: $!"
        else
            $qadenascripts/run_signerenclave.sh &
            PIDS+=$!
            PROC_NAMES[$!]="run_signerenclave.sh"
            echo "run.sh: signer enclave started by script, PID: $!"
        fi
fi

# check if the signer enclave is up
IS_UP=0
for i in {90..1}
do
    # check via curl
    curl -s http://localhost:26661/ping > /dev/null
    if [ $? -eq 0 ] ; then
        echo "run.sh: signer_enclave is up and running!"
        IS_UP=1
        break
    else
        echo "run.sh: signer_enclave is not yet up, waiting...$i"
        sleep 1
    fi
done
if [ $IS_UP -ne 1 ] ; then
    echo "run.sh: Could not run the signer_enclave"
    exit 1
fi

if [[ $SYNC_WITH_PIONEER != "" ]] ; then
    $qadenascripts/delayed_init_enclave.sh --sync-with-pioneer $SYNC_WITH_PIONEER &
else
    $qadenascripts/delayed_init_enclave.sh &
fi
PIDS+=$!
PROC_NAMES[$!]="delayed_init_enclave.sh"
echo "run.sh: delayed_init_enclave.sh started, PID: $!"

echo "run.sh: ------------"
echo "run.sh: START QADENA"
echo "run.sh: ------------"
echo "run.sh: ------------"

if [[ $REAL_ENCLAVE == 1 ]] ; then
    qadenad_alias start --api.enable=true --grpc.enable=true --grpc.address 0.0.0.0:9090 --enclave-addr localhost:50051 --enclave-signer-id `ego signerid $QADENAHOME/config/public.pem` --enclave-unique-id `ego uniqueid $qadenabin/qadenad_enclave` --home=$QADENAHOME &
    PIDS+=$!
    PROC_NAMES[$!]="qadenad (real enclave)"
else
    qadenad_alias start --api.enable=true --grpc.enable=true --grpc.address 0.0.0.0:9090 --enclave-addr localhost:50051 --home=$QADENAHOME &
    PIDS+=$!
    PROC_NAMES[$!]="qadenad"
fi

trap 'echo "run.sh: Got SIGINT"; KILLED=1' SIGINT

# Monitor all background PIDs
KILLED=0

# while not KILLED
while [ $KILLED -eq 0 ] ; do
  for pid in ${PIDS[@]}; do
    if ! kill -0 $pid 2>/dev/null; then
      wait $pid
      RC=$?

      proc_name=${PROC_NAMES[$pid]}
      # if proc_name is delayed_init_enclave.sh, and RC is 0, report is as normal exit
      if [ "$proc_name" = "delayed_init_enclave.sh" ] && [ $RC -eq 0 ] ; then
        echo "run.sh: Process ${proc_name} (PID $pid) is done."
      else
        echo "run.sh: Process ${proc_name} (PID $pid) has exited with RC $RC."
      fi

      # remove $pid from arrays
      unset "PROC_NAMES[$pid]"
      new_PIDS=()
      for p in "${PIDS[@]}"; do
        [[ "$p" != "$pid" ]] && new_PIDS+=("$p")
      done
      PIDS=("${new_PIDS[@]}")
    fi
  done

  if [ -z "$PIDS" ] ; then
    KILLED=1
  else
    # display PIDS
    # echo "run.sh: PIDs: '$PIDS'"
  fi
  sleep 2
done

echo "run.sh: -----------"
echo "run.sh: STOP CHAIN"
echo "run.sh: -----------"
echo "run.sh: -----------"

trap SIGINT

if [[ $DEBUG != "no_qadenad_enclave" ]] ; then
    echo "run.sh: Stopping Qadena"
    $qadenascripts/stop_qadena.sh --all
else
    echo "run.sh: Won't stop Enclave, this script didn't start it."
fi
