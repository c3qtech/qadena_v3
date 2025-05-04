#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

# if REAL_ENCLAVE, check if running as root
if [[ $REAL_ENCLAVE -eq 1 ]]; then
    if [[ $(id -u) -ne 0 ]]; then
        echo "stop_chain.sh:  Error: qadenad_enclave must be run as root"
        exit 1
    fi
fi

# get argument "--enclave-only"
stop_enclave=0
stop_chain=0
stop_init_enclave=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --enclave)
      stop_enclave=1
      shift
      ;;
    --chain)
      stop_chain=1
      shift
      ;;
    --init-enclave)
      stop_init_enclave=1
      shift
      ;;
    --all)
      stop_enclave=1
      stop_chain=1
      stop_init_enclave=1
      shift
      ;;
    --help)
      echo "stop_chain.sh:  Usage: stop_chain.sh [--enclave] [--chain] [--init-enclave]"
      exit 0
      ;;      
    *)
      echo "stop_chain.sh:  Unknown option: $1"
      exit 1
      ;;
  esac
done

if [[ $stop_chain -eq 0 && $stop_enclave -eq 0 && $stop_init_enclave -eq 0 ]] ; then
    # assume all
    stop_chain=1
    stop_enclave=1
    stop_init_enclave=1
fi


echo "stop_chain.sh: -----------"
echo "stop_chain.sh: STOP CHAIN"
echo "stop_chain.sh: -----------"

if [[ $stop_chain -eq 1 ]] ; then
    echo "stop_chain.sh: Stopping Qadena"
    pkill -INT -f "qadenad"
fi

if [[ $stop_enclave -eq 1 ]] ; then
    echo "stop_chain.sh: Stopping Qadena Enclave"
    if [[ $REAL_ENCLAVE == 1 ]] ; then
      pkill -INT -f "/opt/ego/bin/ego-host"
    else  
      pkill -INT -f "qadenad_enclave"
    fi
fi

if [[ $stop_init_enclave -eq 1 ]] ; then
    echo "stop_chain.sh: Stopping Qadena Init Enclave"
    pkill -INT -f "delayed_init_enclave.sh"
fi

# stop rotatelogs
# if rotatelogs is running, stop it

#detect if rotatelogs is running
pgrep -f "rotatelogs.*qadena" > /dev/null
if [[ $? -eq 0 ]]; then
    echo "stop_chain.sh: Stopping rotatelogs"
    pkill -f "rotatelogs.*qadena"
fi
