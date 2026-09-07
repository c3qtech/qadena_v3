#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

# Capture before sourcing: setup_env defaults the backend to `test` for the harness, so a later
# ${QADENA_KEYRING_BACKEND:-file} would never see the caller's choice.
_kb_caller="${QADENA_KEYRING_BACKEND:-}"
source "$SCRIPT_DIR/../scripts/setup_env.sh"
export QADENA_KEYRING_BACKEND="${_kb_caller:-file}"

# Default provider name
provider="secidentitysrvprv"
count=10
include_base_provider=false
include_base_provider_credential=false
json=false

# Process command line arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --keyring-passfile)
            export QADENA_KEYRING_PASSFILE="$2"
            shift 2
            ;;
        --include-base-provider)
            include_base_provider=true
            shift
            ;;
        --include-base-provider-credential)
            include_base_provider_credential=true
            shift
            ;;
        --provider)
            provider="$2"
            shift 2
            ;;
        --count)
            count="$2"
            shift 2
            ;;
        --json)
            json=true
            shift
            ;;
        --help)
            echo "Usage: $0 [--provider <providername>] [--count <count>] [--json]"  >&2
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            echo "Usage: $0 [--provider <providername>] [--count <count>] [--json]" >&2
            exit 1
            ;;
    esac
done

# ASK FOR THE PASSPHRASE IF NOBODY SUPPLIED ONE.
#
# This exports PRIVATE KEYS from the keyring, so on the encrypted backend it needs the
# passphrase.  Run from step_3 the caller has already unlocked it; run BY HAND -- which is the
# normal way to regenerate the .base64 files after a deployment -- nothing had, and qadenad
# prompted once PER KEY into whatever stdin the call site happened to have.  With output
# captured (which it is, three lines below) those prompts are invisible and the run looks hung.
#
# qadena_keyring_unlock asks once, on the terminal, and refuses with the remedy when there is no
# terminal to ask on.  --keyring-passfile skips the prompt for an unattended run.
qadena_keyring_unlock


# Generate names array
names=()
# Check if provider contains the %d placeholder
if [[ "$provider" == *#* ]]; then
    echo "Provider name contains %d placeholder" >&2
    # For the base provider, replace %d with nothing
    base_provider=${provider//\#/}
    
    if [ "$include_base_provider" = true ]; then
        names+=("$base_provider")
    fi

    if [ "$include_base_provider_credential" = true ]; then
        names+=("$base_provider-credential")
    fi

    # For ephemeral keys, replace %d with the number
    for i in $(seq 1 $count); do
        curr_name=${provider//\#/-eph$i}
        names+=("$curr_name")
    done
else
        # Original behavior if no %d is present
    for i in $(seq 1 $count); do
        names+=("$provider-eph$i")
    done
fi

# Create JSON array of names
names_json=$(printf '%s\n' "${names[@]}" | jq -R . | jq -s .)
names_base64=$(echo "$names_json" | base64 -w 0)

echo "Names JSON array:" >&2
echo "$names_json" >&2
echo >&2
echo "Names Base64:" >&2
if [ "$json" = true ]; then
  echo '{'
  echo '  "names": "'$names_base64'",'
else
  echo "$names_base64"
fi
echo >&2

# Extract private keys
echo "Extracting private keys..." >&2
keys=()
for name in "${names[@]}"; do
    echo "Processing $name..." >&2
    # THE ARMOR PASSPHRASE IS THE KEYRING PASSPHRASE.  This line used to pipe
    # `echo "dummy-passphrase"` in, which read as though it chose the armor passphrase.  It never
    # did: qadenad_alias supplies its OWN stdin -- the keyring passphrase, repeated for however
    # many prompts a command has -- and that overrides the pipe.  The armor was always encrypted
    # with the keyring passphrase, so the echo documented a fiction.
    #
    # It matters downstream: the app-server imports these with ARMOR_PASS_PHRASE and dies at
    # startup on a mismatch, reporting "Failed to import private key for <name>:" with an EMPTY
    # reason.  Anyone reading the old line would have set that variable to "dummy-passphrase" and
    # been wrong -- which is exactly what shipped (measured 2026-09-07: api in a restart loop).
    # Pass the same passfile to patch_env_file.sh --armor-passfile and the two stay in step.
    #
    # `if key=$(...)` rather than a later `$?`: the old check tested the status of the ASSIGNMENT,
    # so a failed export stored whatever $key held and was reported as success.
    if key=$(qadenad_alias keys export "$name" 2>/dev/null); then
        # Replace actual newlines and carriage returns with literal escape sequences
        # Using perl for macOS compatibility with multiline replacements
        key=$(echo "$key" | perl -pe 's/\n/\\\\n/g' | perl -pe 's/\r/\\\\r/g')
        # Store the entire key as a single element with newline characters converted to \n literals
        keys+=("$key")
    else
        echo "Error exporting key for $name" >&2
        keys+=("error")
    fi
done

# Create JSON array of keys, preserving each key as a single element
keys_json=$(for key in "${keys[@]}"; do echo -n "$key" | jq -Rs .; done | jq -s .)
keys_base64=$(echo "$keys_json" | base64 -w 0)

echo "Private keys JSON array:" >&2
echo "$keys_json" >&2
echo >&2
echo "Private keys Base64:" >&2
if [ "$json" = true ]; then
    echo '  "private_keys": "'$keys_base64'"'
    echo '}'
else
    echo "$keys_base64"
fi

# remove the "#" from the provider name
provider_no_hash=${provider//\#/}
echo "Provider name without hash: $provider_no_hash" >&2
echo "$names_base64" > "${provider_no_hash}-names.base64"
echo "$keys_base64" > "${provider_no_hash}-keys.base64"

