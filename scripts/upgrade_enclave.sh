#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

FROM_ENCLAVE_UNIQUE_ID=""

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
    --help)
      echo "Usage: upgrade_enclave.sh [--from-enclave-unique-id <unique-id>]"
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

# run the old enclave
# The OLD and NEW enclaves are judged SEPARATELY, because they are separate binaries and can
# legitimately disagree mid-upgrade -- the old one signed and the new one debug, or the reverse.
#
# old_is_sgx is recorded rather than re-evaluated later: the kill at the end of this script must
# match whichever way this branch actually went.  Re-testing there could pick the other arm (the
# binary can be replaced underneath us) and leave the old enclave running.
if use_real_enclave "$qadenabin/qadenad_enclave.$FROM_ENCLAVE_UNIQUE_ID" ; then
    old_is_sgx=1
    ego run $qadenabin/qadenad_enclave.$FROM_ENCLAVE_UNIQUE_ID --realenclave --home=$QADENAHOME --chain-id=$CHAINID --upgrade-mode &
    pid=$!
else
    old_is_sgx=0
    $qadenabin/qadenad_enclave.$FROM_ENCLAVE_UNIQUE_ID --home=$QADENAHOME --chain-id=$CHAINID --upgrade-mode &
    pid=$!
fi

# wait for the enclave to start
# wait for socket to come up
IS_UP=0
for i in {90..1}
do
    if [[ "$(uname -s)" == "Darwin" ]] ; then
	listen=`netstat -an`
    else
	listen=`netstat -l`
    fi
    
    if echo $listen | grep 50051 > /dev/null ; then
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

if use_real_enclave "$qadenabin/qadenad_enclave" ; then
  ego run $qadenabin/qadenad_enclave --realenclave --home=$QADENAHOME --chain-id=$CHAINID --upgrade-from-enclave-unique-id=$FROM_ENCLAVE_UNIQUE_ID
else
  $qadenabin/qadenad_enclave --home=$QADENAHOME --chain-id=$CHAINID --upgrade-from-enclave-unique-id=$FROM_ENCLAVE_UNIQUE_ID
fi

RES=$?

# kill the old enclave
# Matches how the old enclave was actually STARTED above, not how it would be judged now.
if [[ $old_is_sgx -eq 1 ]] ; then
    pkill -INT -f "/opt/ego/bin/ego-host"
else
    pkill -INT -f "qadenad_enclave.$FROM_ENCLAVE_UNIQUE_ID"
fi

exit $RES

