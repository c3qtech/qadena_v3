#!/bin/zsh

./test_realenclave.sh
REAL_ENCLAVE=$?

if [[ $REAL_ENCLAVE == 1 ]] ; then
    echo "---------------------------------------"
    echo "BUILD REAL EKYC ENCLAVE (ego-go/ego toolset)"
    echo "---------------------------------------"
    export enclave_path="$(pwd)/cmd/qadena_ekyc"
    echo "Enclave path: $enclave_path"
    ego-go build -o $enclave_path/qadena_ekyc -mod readonly qadena_v3/cmd/qadena_ekyc || exit 1
    cd $enclave_path
    echo "Signing qadenad_enclave executable"
    ego sign qadena_ekyc || exit 1
else
    echo "-------------------"
    echo "BUILD DEBUG EKYC ENCLAVE"
    echo "-------------------"
    export user_go_path="$(cd ~ && pwd)/go/bin"
    echo "User GO path: $user_go_path"
    go build -o $user_go_path/qadena_ekyc -mod readonly qadena_v3/cmd/qadena_ekyc || exit 1
fi
