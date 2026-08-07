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

# Idempotent. `keys add --recover` prompts "override the existing name X? [y/N]" when
# the key is already in the keyring, and stdin here is the piped mnemonic -- so the
# mnemonic itself gets eaten as the answer, which is not "y", and the whole thing dies
# with "key overwrite confirmation for X aborted". That aborts the CALLER too, so
# re-running setup_enf.sh / setup_veritas.sh on a machine that already has the keys
# stops before doing any of the work it was asked to do.
#
# The mnemonic is a fixed literal, so an existing key of this name should already be
# the right one -- but that is verified rather than assumed, because silently using
# somebody else's key of the same name would be far worse than stopping.
if qadenad_alias keys show "$name" > /dev/null 2>&1; then
    existing_addr=$(qadenad_alias keys show "$name" --address)
    expected_addr=$(echo "$treasury_mnemonic" | qadenad_alias keys add "$name" --recover --dry-run --output json 2>/dev/null | jq -r '.address // empty')
    if [ -n "$expected_addr" ] && [ "$existing_addr" != "$expected_addr" ]; then
        echo "FAILED: key '$name' already exists but is NOT the one this mnemonic derives"
        echo "  in keyring: $existing_addr"
        echo "  expected:   $expected_addr"
        echo "  delete it first:  qadenad keys delete $name"
        exit 1
    fi
    echo "$name key already exists ($existing_addr) -- skipping keys add"
else
    echo "$treasury_mnemonic" | qadenad_alias keys add "$name" --recover
fi

qadena_addr=$(qadenad_alias keys show $name --address)
echo "created $name with address $qadena_addr"
echo "Send the treasury address $qadena_addr to the Qadena foundation"
