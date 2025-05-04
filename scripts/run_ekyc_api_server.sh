#!/bin/zsh

export user_go_path="$(cd ~ && pwd)/go/bin"
echo "User GO path: $user_go_path"

ARG1=$1

if [[ ! ($ARG1 == "debug_ekyc_api_server" || $ARG1 == "") ]] ; then
    echo "Usage:  run_enclave.sh [debug_ekyc_api_server]"
    exit 1
fi

ekychome="$(cd ~ && pwd)/.ekyc"
$QADENAHOME="$(cd ~ && pwd)/.qadena"

EKYCNAME="r-ekyc-app"

if [[ ! -d "$ekychome" ]] ; then
    mkdir "$ekychome"
fi

if [[ ! -d "$ekychome/enclave_config" ]] ; then
    mkdir "$ekychome/enclave_config"
fi

if [[ ! -d "$ekychome/enclave_data" ]] ; then
    mkdir "$ekychome/enclave_data"
fi

if [[ ! -d "$ekychome/uploads" ]] ; then
    mkdir "$ekychome/uploads"
fi


if [[ "$(uname -s)" == "Darwin" ]] ; then
    echo -n -e "\033]0;QADENA EKYC Enclave Debug Window\007"
fi

cmd=$user_go_path/qadena_ekyc
cmdx1=
cmdx2=

if [[ $ARG1 == "debug_ekyc_api_server" ]] ; then
    cmd="gdlv"
    cmdx1="exec"
    cmdx2=$user_go_path/qadena_ekyc
fi

VALUE=`cat $QADENAHOME/config/genesis.json | jq '.chain_id'`
temp="${VALUE%\"}"
temp="${temp#\"}"
echo "CHAINID=$temp"
CHAINID=$temp

privkhex=$(echo "dummy-passphrase" | qadenad keys export $EKYCNAME)

#echo "PRIVKHEX $privkhex"

if [[ $privkhex == "" || CHAINID == "" ]] ; then
    echo "FAILED TO GET KEYS OR CHAINID"
    exit 1
fi

$cmd $cmdx1 $cmdx2 --home=$ekychome --chain-id=$CHAINID --ekyc-name=$EKYCNAME --ekyc-armor-privk "$privkhex" --ekyc-armor-passphrase "dummy-passphrase"


