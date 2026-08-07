#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

# Root is needed only when we will actually run an ego enclave -- i.e. SGX hardware AND a signed
# binary.  See use_real_enclave in setup_env.sh: REAL_ENCLAVE alone only says the CPU supports SGX,
# not that this binary was built for it.
warn_if_sgx_binary_missing "run.sh" "$qadenabin/qadenad_enclave"
needs_root_if_real_enclave "run.sh" "$qadenabin/qadenad_enclave"

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
        if use_real_enclave "$qadenabin/qadenad_enclave" ; then
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
        # gated on signer_enclave, not qadenad_enclave: they are separate binaries and can be built
        # differently, so one being signed says nothing about the other
        if use_real_enclave "$qadenabin/signer_enclave" ; then
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

# read the config and check log level
log_level=$(grep "log_level" $QADENAHOME/config/config.toml | awk '{print $3}' | tr -d '"' | tr -d "'")
if [[ $log_level == "debug" ]] ; then
    log_level="debug"
else
    log_level="info"
fi


if use_real_enclave "$qadenabin/qadenad_enclave" ; then
    # SUBSTITUTED INLINE, THESE FAIL SILENTLY.  `ego signerid` writes "ERROR: reading key file: ..."
    # to STDOUT (not stderr) and exits 1, so a missing public.pem used to become the literal
    # argument `--enclave-signer-id ERROR:` with the rest of the message trailing as stray
    # positional args -- and the node started anyway, because keeper.InitEnclave takes the
    # unix-domain-socket branch and never reads the value.  Extract first, and say so if it failed.
    signer_id=`ego signerid $QADENAHOME/config/public.pem` || signer_id=""
    unique_id=`ego uniqueid $qadenabin/qadenad_enclave` || unique_id=""
    if [[ -z "$signer_id" || "$signer_id" == ERROR:* ]]; then
        echo "run.sh: WARNING: could not read a signer id from $QADENAHOME/config/public.pem"
        echo "run.sh:          ($signer_id)"
        echo "run.sh:          Starting anyway -- the chain reaches its enclave over a unix domain"
        echo "run.sh:          socket and does not check this today -- but reinstall public.pem."
        signer_id=""
    fi
    if [[ -z "$unique_id" || "$unique_id" == ERROR:* ]]; then
        echo "run.sh: WARNING: could not read a unique id from $qadenabin/qadenad_enclave ($unique_id)"
        unique_id=""
    fi
    qadenad_alias start --json-rpc.api eth,txpool,personal,net,debug,web3 --api.enable=true --grpc.enable=true --grpc.address 0.0.0.0:9090 --enclave-addr localhost:50051 --enclave-signer-id "$signer_id" --enclave-unique-id "$unique_id" --home=$QADENAHOME --log-level $log_level &
    PIDS+=$!
    PROC_NAMES[$!]="qadenad (real enclave)"
else
    qadenad_alias start --json-rpc.api eth,txpool,personal,net,debug,web3 --api.enable=true --grpc.enable=true --grpc.address 0.0.0.0:9090 --enclave-addr localhost:50051 --home=$QADENAHOME --log-level $log_level &
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

echo "run.sh: ------------"
echo "run.sh: QADENA ENDED "
echo "run.sh: ------------"
echo "run.sh: ------------"

trap SIGINT

if [[ $DEBUG != "no_qadenad_enclave" ]] ; then
    echo "run.sh: Stopping Qadena"
    $qadenascripts/stop_qadena.sh --all
else
    echo "run.sh: Won't stop Enclave, this script didn't start it."
fi
