#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh" > /dev/null 2>&1

external_url=$(grep "external_address" $QADENAHOME/config/config.toml | awk '{print $3}')
temp="${external_url%\"}"
temp="${temp#\"}"
external_address=$(echo $temp | awk -F'[:]' '{print $1}')
if [[ $external_address == "" ]] ; then
    exit 1
fi
echo $external_address
