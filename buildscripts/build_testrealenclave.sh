#!/bin/zsh

export user_go_path="$(cd ~ && pwd)/go/bin"
echo "User GO path: $user_go_path"
go build -o $user_go_path/test_realenclave -mod readonly github.com/c3qtech/qadena_v3/cmd/test_realenclave
