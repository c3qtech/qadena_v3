#!/bin/zsh

export user_go_path="$(cd ~ && pwd)/go/bin"
echo "User GO path: $user_go_path"
go build -o $user_go_path/test_enclave -mod readonly qadena/cmd/test_enclave
