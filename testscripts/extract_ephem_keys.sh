#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

# Default provider name
provider="secidentitysrvprv"
count=10

# Process command line arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --provider)
            provider="$2"
            shift 2
            ;;
        --count)
            count="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [--provider <providername>] [--count <count>]"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--provider <providername>] [--count <count>]"
            exit 1
            ;;
    esac
done

# Generate names array
names=()
# Check if provider contains the %d placeholder
if [[ "$provider" == *#* ]]; then
    # For the base provider, replace %d with nothing
    base_provider=${provider//\#/}
    names+=("$base_provider")
    
    # For ephemeral keys, replace %d with the number
    for i in $(seq 1 $count); do
        curr_name=${provider//\#/-eph$i}
        names+=("$curr_name")
    done
else
    # Original behavior if no %d is present
    names+=("$provider")
    for i in $(seq 1 $count); do
        names+=("$provider-eph$i")
    done
fi

# Create JSON array of names
names_json=$(printf '%s\n' "${names[@]}" | jq -R . | jq -s .)
names_base64=$(echo "$names_json" | base64)

echo "Names JSON array:"
echo "$names_json"
echo
echo "Names Base64:"
echo "$names_base64"
echo

# Extract private keys
echo "Extracting private keys..."
keys=()
for name in "${names[@]}"; do
    echo "Processing $name..."
    # Use a dummy passphrase to export the key
    key=$(echo "dummy-passphrase" | qadenad_alias keys export "$name" 2>/dev/null)
    
    if [ $? -eq 0 ]; then
        # Replace actual newlines and carriage returns with literal escape sequences
        # Using perl for macOS compatibility with multiline replacements
        key=$(echo "$key" | perl -pe 's/\n/\\\\n/g' | perl -pe 's/\r/\\\\r/g')
        # Store the entire key as a single element with newline characters converted to \n literals
        keys+=("$key")
    else
        echo "Error exporting key for $name"
        keys+=("error")
    fi
done

# Create JSON array of keys, preserving each key as a single element
keys_json=$(for key in "${keys[@]}"; do echo -n "$key" | jq -Rs .; done | jq -s .)
keys_base64=$(echo "$keys_json" | base64)

echo "Private keys JSON array:"
echo "$keys_json"
echo
echo "Private keys Base64:"
echo "$keys_base64"
