#!/bin/zsh

set -e


# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

# Process named options
while [[ $# -gt 0 ]]; do
    case "$1" in
        --treasury-name)
            treasury_name="$2"
            shift 2
            ;;
        --treasury-mnemonic)
            treasury_mnemonic="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [--treasury-name <treasury name>] [--treasury-mnemonic <treasury mnemonic>]"
            exit 0
            ;;
        --*) # Handle unknown options
            echo "Unknown option: $1"
            shift 1
            ;;
        *) # Skip positional parameters (already handled above)
            shift 1
            ;;
    esac
done

if [ -z "$treasury_name" ]; then
    echo "Usage: $0 --treasury-name <treasury name>"
    exit 1
fi

if [ -z "$treasury_mnemonic" ]; then
    echo "Usage: $0 --treasury-mnemonic <treasury mnemonic>"
    exit 1
fi

name="$treasury_name"

echo $treasury_mnemonic | qadenad_alias keys add $name --recover

qadena_addr=$(qadenad_alias keys show $name --address)
echo "created $name with address $qadena_addr"
echo "Send the treasury address $qadena_addr to the Qadena foundation"
