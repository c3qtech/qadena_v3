#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

# Default provider name
provider="secidentitysrvprv"
count=10
include_base_provider=false
include_base_provider_credential=false
json=false

# Process command line arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
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
    # Use a dummy passphrase to export the key
    key=$(echo "dummy-passphrase" | qadenad_alias keys export "$name" 2>/dev/null)
    
    if [ $? -eq 0 ]; then
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
