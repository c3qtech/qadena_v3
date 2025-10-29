#!/bin/zsh

set -e

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

# Default environment type and count
env_type="staging"
count=2
input_template=""

# Process command line arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --env-type)
            env_type="$2"
            shift 2
            ;;
        --count)
            count="$2"
            shift 2
            ;;
        --input-template)
            input_template="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [--env-type <staging|production>] [--count <count>] [--input-template <file>]"
            echo "Generates AWS CloudFormation template with extracted ephemeral keys"
            echo "  --env-type: Environment type (staging or production)"
            echo "  --count: Number of ephemeral keys to extract per service (default: 2)"
            echo "  --input-template: Input CloudFormation template to update (default: v2-cloud-formation-ssm-parameters.yml)"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--env-type <staging|production>] [--count <count>] [--input-template <file>]"
            exit 1
            ;;
    esac
done

echo "Generating AWS CloudFormation template for environment: $env_type"
echo "============================================================"

# Function to extract a single key and encode it in base64
extract_key() {
    local key_name="$1"
    echo "Extracting key for: $key_name"
    
    # Use a dummy passphrase to export the key
    local key=$(echo "dummy-passphrase" | qadenad_alias keys export "$key_name" 2>/dev/null)
    
    if [ $? -eq 0 ]; then
        # Encode the key in base64
        echo "$key" | base64 | tr -d '\n'
    else
        echo "ERROR: Failed to extract key for $key_name" >&2
        echo "KEY_EXTRACTION_ERROR"
    fi
}

# Function to extract username (key name)
extract_username() {
    local key_name="$1"
    echo "$key_name" | base64 | tr -d '\n'
}

# Function to extract multiple ephemeral keys for a provider
extract_provider_keys() {
    local provider="$1"
    local key_count="$2"
    local include_base="$3"  # Optional parameter: "include-base-provider"
    local usernames=()
    local private_keys=()
    
    # echo to stderr
    echo "Extracting keys for provider: $provider (count: $key_count)" >&2
    
    # Extract base provider key if requested
    if [ "$include_base" = "include-base-provider" ]; then
        echo "  Processing base provider: $provider..." >&2
        usernames+=("$provider")
        
        local base_private_key=$(echo "dummy-passphrase" | qadenad_alias keys export "$provider" 2>/dev/null)
        if [ $? -eq 0 ]; then
            # Convert actual newlines to literal \n strings for JSON
            base_private_key=$(echo "$base_private_key" | perl -pe 's/\n/\\\\n/g')
            private_keys+=("$base_private_key")
        else
            echo "ERROR: Failed to extract base key for $provider" >&2
            private_keys+=("KEY_EXTRACTION_ERROR")
        fi
    fi
    
    # Extract ephemeral keys
    for i in $(seq 1 $key_count); do
        local key_name="${provider}-eph${i}"
        echo "  Processing $key_name..." >&2
        
        # Store the raw key name (not base64 encoded)
        usernames+=("$key_name")
        
        # Extract the raw private key and convert newlines to \n literals
        local private_key=$(echo "dummy-passphrase" | qadenad_alias keys export "$key_name" 2>/dev/null)
        if [ $? -eq 0 ]; then
            # Convert actual newlines to literal \n strings for JSON
            # Use double escaping to ensure \n appears in the final output
            private_key=$(echo "$private_key" | perl -pe 's/\n/\\\\n/g')
            private_keys+=("$private_key")
        else
            echo "ERROR: Failed to extract key for $key_name" >&2
            private_keys+=("KEY_EXTRACTION_ERROR")
        fi
    done
    
    # Create JSON arrays and base64 encode them
    local usernames_json=$(printf '%s\n' "${usernames[@]}" | jq -R . | jq -s .)
    local keys_json=$(printf '%s\n' "${private_keys[@]}" | jq -R . | jq -s .)
    
    local usernames_base64=$(echo "$usernames_json" | base64 | tr -d '\n')
    local keys_base64=$(echo "$keys_json" | base64 | tr -d '\n')
    
    # Return as pipe-separated string
    echo "$usernames_base64|$keys_base64"
}

# Extract keys for different services
echo "Extracting keys for all provider types..."

# Extract secidentitysrvprv# keys
echo "Extracting secidentitysrvprv# keys..."
secidentity_result=$(extract_provider_keys "secidentitysrvprv" "$count" "include-base-provider")
secidentity_usernames=$(echo "$secidentity_result" | cut -d'|' -f1)
secidentity_private_keys=$(echo "$secidentity_result" | cut -d'|' -f2)

# Extract secdsvssrvprv# keys  
echo "Extracting secdsvssrvprv# keys..."
secdsvssrvprv_result=$(extract_provider_keys "secdsvssrvprv" "$count" "include-base-provider")
secdsvssrvprv_usernames=$(echo "$secdsvssrvprv_result" | cut -d'|' -f1)
secdsvssrvprv_private_keys=$(echo "$secdsvssrvprv_result" | cut -d'|' -f2)

# Extract sec-create-wallet-sponsor# keys
echo "Extracting sec-create-wallet-sponsor# keys..."
wallet_sponsor_result=$(extract_provider_keys "sec-create-wallet-sponsor" "$count" "include-base-provider")
wallet_sponsor_usernames=$(echo "$wallet_sponsor_result" | cut -d'|' -f1)
wallet_sponsor_private_keys=$(echo "$wallet_sponsor_result" | cut -d'|' -f2)

# Extract secdsvs# keys
echo "Extracting secdsvs# keys..."
secdsvs_result=$(extract_provider_keys "secdsvs" "$count")
secdsvs_usernames=$(echo "$secdsvs_result" | cut -d'|' -f1)
secdsvs_private_keys=$(echo "$secdsvs_result" | cut -d'|' -f2)

# Extract secdsvs#-credential keys
echo "Extracting secdsvs#-credential keys..."
secdsvs_cred_result=$(extract_provider_keys "secdsvs" "$count")
# For credential keys, we need to modify the usernames to add -credential suffix
secdsvs_cred_usernames=$(echo "$secdsvs_cred_result" | cut -d'|' -f1 | base64 --decode | jq -r '.[] | . + "-credential"' | jq -R . | jq -s . | base64 | tr -d '\n')
secdsvs_cred_private_keys=$(echo "$secdsvs_cred_result" | cut -d'|' -f2)

# Debug output
echo "=== DEBUG OUTPUT ===" >&2
echo "secidentitysrvprv usernames: $(echo "$secidentity_usernames" | base64 --decode)" >&2
echo "secidentitysrvprv private keys: $(echo "$secidentity_private_keys" | base64 --decode)" >&2
echo "secdsvssrvprv usernames: $(echo "$secdsvssrvprv_usernames" | base64 --decode)" >&2
echo "secdsvssrvprv private keys: $(echo "$secdsvssrvprv_private_keys" | base64 --decode)" >&2
echo "wallet sponsor usernames: $(echo "$wallet_sponsor_usernames" | base64 --decode)" >&2
echo "wallet sponsor private keys: $(echo "$wallet_sponsor_private_keys" | base64 --decode)" >&2
echo "secdsvs usernames: $(echo "$secdsvs_usernames" | base64 --decode)" >&2
echo "secdsvs private keys: $(echo "$secdsvs_private_keys" | base64 --decode)" >&2
echo "secdsvs credential usernames: $(echo "$secdsvs_cred_usernames" | base64 --decode)" >&2
echo "secdsvs credential private keys: $(echo "$secdsvs_cred_private_keys" | base64 --decode)" >&2


# Generate CloudFormation template
template_file="veritas-keys-${env_type}-updated.yaml"

# Check if input template exists
if [ -f "$input_template" ]; then
    echo "Reading existing template: $input_template"
    # Copy the input template as base
    cp "$input_template" "$template_file"
    
    # Function to update parameter value in YAML
    update_parameter_value() {
        local param_name="$1"
        local new_value="$2"
        local temp_file=$(mktemp)
        
        # Use awk to properly handle both simple Value and !Join formats
        awk -v param="$param_name" -v value="$new_value" '
        BEGIN { 
            in_param = 0
            in_join_array = 0
            skip_lines = 0
        }
        
        # Found the parameter we want to update
        /Name:.*/ && $0 ~ param { 
            in_param = 1
            print
            next 
        }
        
        # Handle simple Value: format
        in_param && /Value:/ && !/!Join/ { 
            print "      Value: \"" value "\""
            in_param = 0
            next 
        }
        
        # Handle !Join Value format - start of multi-line value
        in_param && /Value: !Join/ {
            print "      Value: \"" value "\""
            in_join_array = 1
            skip_lines = 1
            in_param = 0
            next
        }
        
        # Skip lines that are part of the !Join array
        skip_lines && /^        / { next }
        skip_lines && /^      \]/ { 
            skip_lines = 0
            in_join_array = 0
            next 
        }
        
        # Exit parameter context when we hit the next resource
        in_param && /^  [A-Za-z]/ && !/Properties:/ && !/Type:/ { 
            in_param = 0
        }
        
        # Print all other lines
        { print }
        ' "$template_file" > "$temp_file"
        mv "$temp_file" "$template_file"
    }
    
    # Update parameter values with extracted keys
    echo "Updating parameter values..."
    update_parameter_value "SEC_DSVS_EPH_USERNAME" "$secdsvs_usernames"
    update_parameter_value "SEC_DSVS_EPH_PRIVATE_KEY" "$secdsvs_private_keys"
    update_parameter_value "SEC_DSVS_EPH_CREDENTIAL_USERNAME" "$secdsvs_cred_usernames"
    update_parameter_value "SEC_DSVS_EPH_CREDENTIAL_PRIVATE_KEY" "$secdsvs_cred_private_keys"
    update_parameter_value "SEC_DSVS_SRV_PRV_USERNAME" "$secdsvssrvprv_usernames"
    update_parameter_value "SEC_DSVS_SRV_PRV_PRIVATE_KEY" "$secdsvssrvprv_private_keys"
    update_parameter_value "SEC_IDENTITY_SRV_PRV_USERNAME" "$secidentity_usernames"
    update_parameter_value "SEC_IDENTITY_SRV_PRV_PRIVATE_KEY" "$secidentity_private_keys"
    update_parameter_value "SEC_CREATE_WALLET_SPONSOR_USERNAME" "$wallet_sponsor_usernames"
    update_parameter_value "SEC_CREATE_WALLET_SPONSOR_PRIVATE_KEY" "$wallet_sponsor_private_keys"
    
    echo "Template updated: $template_file"
else
    echo "Error: Input template '$input_template' not found!"
    echo "Please provide a valid CloudFormation template file."
    exit 1
fi

echo ""
echo "CloudFormation template generated: $template_file"
echo ""
echo "Key extraction summary:"
echo "- DSVS Ephemeral Keys: secdsvssrvprv-eph1 to secdsvssrvprv-eph${count} (${count} keys)"
echo "- DSVS Service Provider: secdsvssrvprv"
echo "- Identity Service Provider: secidentitysrvprv"
echo "- Create Wallet Sponsor: createwalletsponsor"

echo ""
echo "All ephemeral keys are stored as base64-encoded JSON arrays."
echo "Template ready for deployment to AWS CloudFormation."
