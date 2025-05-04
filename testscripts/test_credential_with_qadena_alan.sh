#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

set -e

prefix=""

# Parse options
while [[ $# -gt 0 ]]; do
    case "$1" in
        --prefix)
            prefix="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [--prefix <prefix>]"
            echo "--prefix <prefix>: Add a prefix to the test users"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "try: setup_credential.sh --help"
            exit 1
            ;;
    esac
done

if [ -z "$prefix" ]; then
    echo "Missing required option: prefix"
    exit 1
fi



$qadenatestscripts/setup_credential.sh --prefix $prefix --amount 1111$prefix --bf 1111$prefix

cd $qadenabuild/../qadena_alan/cmd
dart create_account.dart 1111$prefix 1111$prefix
