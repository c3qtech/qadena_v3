#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

if ! is_qadena_running; then
    echo "stop_qadena.sh: Qadena is not running"
    exit 0
fi

# if REAL_ENCLAVE, check if running as root
if [[ $REAL_ENCLAVE -eq 1 ]]; then
    if [[ $(id -u) -ne 0 ]]; then
        echo "stop_qadena.sh:  Error: qadenad_enclave must be run as root"
        exit 1
    fi
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

if [[ $stop_qadena -eq 1 ]] ; then
    echo "stop_qadena.sh: Stopping Qadena"
    pkill -INT -f "qadenad"

    # check if qadeand is dead after 2 seconds
    sleep 2
    pgrep -f "qadenad" > /dev/null
    if [[ $? -eq 0 ]]; then
        echo "stop_qadena.sh: Error: qadenad is still running"
        pkill -9 -f "qadenad"
        exit 1
    fi
fi

if [[ $stop_enclave -eq 1 ]] ; then
    echo "stop_qadena.sh: Stopping Qadena Enclave"
    if [[ $REAL_ENCLAVE -eq 1 ]] ; then
      pkill -INT -f "/opt/ego/bin/ego-host"
    else  
      pkill -INT -f "qadenad_enclave"
    fi
fi

if [[ $stop_init_enclave -eq 1 ]] ; then
    echo "stop_qadena.sh: Stopping Qadena Init Enclave"
    pkill -INT -f "delayed_init_enclave.sh"
fi

if [[ $stop_signer_enclave -eq 1 ]] ; then
    echo "stop_qadena.sh: Stopping Qadena Signer Enclave"
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