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


# get advertise ip address
ADVERTISE_IP_ADDRESS=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --advertise-ip-address)
      if [[ -n "$2" && "$2" != --* ]]; then
        ADVERTISE_IP_ADDRESS="$2"
        shift 2
      else
        echo "Error: --advertise-ip-address requires an IP argument"
        exit 1
      fi
      ;;
    --help)
      echo "Usage: reset_qadena.sh [--advertise-ip-address <ip>]"
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

if [ -z "$ADVERTISE_IP_ADDRESS" ] ; then
    echo "Error: --advertise-ip-address is required"
    exit 1
fi

echo "Stopping old qadenad and qadenad_enclave"
$qadenascripts/stop_qadena.sh --all
echo "Waiting 5 secs for the chain to die"
sleep 5
echo "Initializing..."
$qadenabuildscripts/init.sh --advertise-ip-address $ADVERTISE_IP_ADDRESS

echo "Restarting..."

$qadenascripts/restart_qadena.sh
echo "Running..."
nohup bash -c "$qadenascripts/run.sh 2>&1 | logger -t qadena" &
echo "Waiting 20 secs for the chain to start"
sleep 20
echo "Setting up secdsvs"
$qadenatestscripts/setup.sh --specific-user secdsvs

