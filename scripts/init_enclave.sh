#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

VALUE=`qadenad_alias status | jq '.node_info.moniker'`
temp="${VALUE%\"}"
temp="${temp#\"}"
echo "init_enclave.sh: PIONEER=$temp"
PIONEER=$temp

JARID="jar1"
REGULATORID="regulator1"

if [[ $1 == "help" ]] ; then
    echo "init_enclave.sh: Usage:  init_enclave.sh [jar-id] [regulator-id]"
    echo "init_enclave.sh:  jar-id default: $JARID"
    echo "init_enclave.sh:  regulator-id default: $REGULATORID"
    exit 1
fi

if [[ $1 != "" ]] ; then
    JARID=$1
fi

if [[ $2 != "" ]] ; then
    REGULATORID=$2
fi


if [[ $PIONEER == "" ]] ; then
    echo "init_enclave.sh: Unable to get the pioneer's moniker"
    exit 1
fi


EXT_ADDR=`$qadenascripts/get_external_address.sh`

if [[ $EXT_ADDR == "" ]] ; then
    echo "init_enclave.sh: Error, config.toml's external_address is not defined.  Try running init.sh"
    exit 1
fi

if [[ $REAL_ENCLAVE == 1 ]] ; then
    echo "init_enclave.sh: Real enclave detected"
    SIGNER_ID=`ego signerid $QADENAHOME/config/public.pem`
    echo "init_enclave.sh: Extracted signer id from $QADENAHOME/config/public.pem: $SIGNER_ID"
    UNIQUE_ID=`ego uniqueid $qadenabin/qadenad_enclave`
    echo "init_enclave.sh: Extracted unique id from $qadenabin/qadenad_enclave: $UNIQUE_ID"
else
    SIGNER_ID="*"
    UNIQUE_ID="*"
fi

qadenad_alias enclave init-enclave --enclave-signer-id $SIGNER_ID --enclave-unique-id $UNIQUE_ID $PIONEER $EXT_ADDR $JARID $REGULATORID 
RET=$?
if [[ $RET != 0 ]] ; then
    echo "init_enclave.sh: qadenad enclave init-enclave failed, need to kill qadenad, qadenad_enclave and signer_enclave"
    pkill -INT -f "qadenad"
    pkill -INT -f "qadenad_enclave"
    pkill -INT -f "signer_enclave"
    exit 1
fi

exit 0
