#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

if [[ $1 == "--help" ]] ; then
    echo "Usage:  export_private_state.sh"
    exit 1
fi

if [[ $REAL_ENCLAVE == 1 ]] ; then
    echo "Real enclave detected"
    enclave_path="$qadenabuild/cmd/qadenad_enclave"
    echo "enclave_path $enclave_path"
    SIGNER_ID=`ego signerid $enclave_path/public.pem`
    echo "Extracted signer id from $enclave_path/public.pem: $SIGNER_ID"
    UNIQUE_ID=`ego uniqueid $enclave_path/qadenad_enclave`
    echo "Extracted unique id from $enclave_path/qadenad_enclave: $UNIQUE_ID"
else
    SIGNER_ID="*"
    UNIQUE_ID="*"
fi

qadenad_alias enclave export-private-state --enclave-signer-id $SIGNER_ID --enclave-unique-id $UNIQUE_ID
