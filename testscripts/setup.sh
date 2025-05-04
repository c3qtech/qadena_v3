#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

# Default values
specific_user=""
prefix=""
no_execute="false"

# Define additional parameters
pioneer="pioneer1"
identityprovider="secidentitysrvprv"
serviceprovider="secdsvssrvprv"


# Parse options
while [[ $# -gt 0 ]]; do
    case "$1" in
        --specific-user)
            specific_user="$2"
            shift 2
            ;;
        --prefix)
            prefix="$2"
            shift 2
            ;;
        --no-execute)
            no_execute="true"
            shift 1
            ;;
        --reset)
            reset="true"
            shift 1
            ;;
        --pioneer)
            pioneer="$2"
            shift 2
            ;;
        --identityprovider)
            identityprovider="$2"
            shift 2
            ;;
        --serviceprovider)
            serviceprovider="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [--specific-user <user>] [--prefix <prefix>] [--reset] [--pioneer <pioneer>] [--identityprovider <identityprovider>] [--serviceprovider <serviceprovider>]"
            echo "--specific-user <user>: Process only the specified user"
            echo "--prefix <prefix>: Add a prefix to the test users"
            echo "--pioneer <pioneer>: Specify the pioneer node"
            echo "--identityprovider <identityprovider>: Specify the identity provider"
            echo "--serviceprovider <serviceprovider>: Specify the service provider"
            echo "--reset: removes all log files and the prefix-generated test users (preserves test_data/users.json)"
            echo "--no-execute: Do not execute the setup"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "try: setup.sh --help"
            exit 1
            ;;
    esac
done

cd $qadenatestscripts/..

# if logs directory doesn't exist, create it
if [ ! -d "logs" ]; then
    echo "Creating logs directory..."
    mkdir logs
fi

if [ -n "$reset" ]; then
    echo "Resetting..."
    # Check if logs directory exists and contains files
    if [ -d "logs" ] && [ "$(find logs -maxdepth 1 -name '*.log' -type f 2>/dev/null | wc -l)" -gt 0 ]; then
        echo "Removing any logs in logs..."    
        rm -f logs/*
    else
            echo "logs directory does not exist or is empty."
    fi

    # Check for any .gen.json files in test_data
    if [ -d "test_data" ] && [ "$(find test_data -maxdepth 1 -name '*.gen.json' -type f 2>/dev/null | wc -l)" -gt 0 ]; then
        echo "Removing any .gen.json files in test_data..."    
        rm -f test_data/*.gen.json
    fi
fi


usersjson="test_data/users.json"


# Output file
output_file="test_data/users${prefix}.gen.json"

# if prefix is not empty and the output_file does not exist, create it
if [ -n "$prefix" ] && [ ! -f "$output_file" ]; then
    echo "Generating file: $output_file"

    # Initialize an empty JSON array
    echo "[]" > "$output_file"

    jq -c '.[]' "$usersjson" | while read -r user; do
        # Extract fields and modify as needed
        name=$(echo "$user" | jq -r '.name')$prefix
        mnemonic=$(qadenad_alias keys mnemonic --keyring-backend test)
        a=$(echo "$user" | jq -r '.a')
        bf=$(echo "$user" | jq -r '.bf')$prefix
        firstname=$(echo "$user" | jq -r '.firstname')$prefix
        middlename=$(echo "$user" | jq -r '.middlename')$prefix
        lastname=$(echo "$user" | jq -r '.lastname')$prefix
        birthdate=$(echo "$user" | jq -r '.birthdate')
        citizenship=$(echo "$user" | jq -r '.citizenship')
        residency=$(echo "$user" | jq -r '.residency')
        gender=$(echo "$user" | jq -r '.gender')
        email=$prefix$(echo "$user" | jq -r '.email')
        phone=$(echo "$user" | jq -r '.phone')$prefix
        acceptcredentialtypes=$(echo "$user" | jq -r '."accept-credential-types" // ""')
        acceptpassword=$(echo "$user" | jq -r '."accept-password" // ""')
        requiresendertypes=$(echo "$user" | jq -r '."require-sender-credential-types" // ""')
        recovery=$(echo "$user" | jq -r 'if .recovery == null then empty else .recovery end')

       # Create a base JSON object
        base_json=$(jq -n \
            --arg name "$name" \
            --arg mnemonic "$mnemonic" \
            --arg a "$a" \
            --arg bf "$bf" \
            --arg firstname "$firstname" \
            --arg middlename "$middlename" \
            --arg lastname "$lastname" \
            --arg birthdate "$birthdate" \
            --arg citizenship "$citizenship" \
            --arg residency "$residency" \
            --arg gender "$gender" \
            --arg email "$email" \
            --arg phone "$phone" \
            --arg acceptcredentialtypes "$acceptcredentialtypes" \
            --arg acceptpassword "$acceptpassword" \
            --arg requiresendertypes "$requiresendertypes" \
            '{
                name: $name,
                mnemonic: $mnemonic,
                a: $a,
                bf: $bf,
                firstname: $firstname,
                middlename: $middlename,
                lastname: $lastname,
                birthdate: $birthdate,
                citizenship: $citizenship,
                residency: $residency,
                gender: $gender,
                email: $email,
                phone: $phone,
                "accept-credential-types": $acceptcredentialtypes,
                "accept-password": $acceptpassword,
                "require-sender-credential-types": $requiresendertypes
            }')
        # Conditionally add "recovery" only if it's not empty
        if [[ -n "$recovery" ]]; then
            new_user_json=$(echo "$base_json" | jq --argjson recovery "$recovery" '. + {recovery: $recovery}')
        else
            new_user_json="$base_json"
        fi

        # Append the new user JSON object to the file
        jq ". + [$new_user_json]" "$output_file" > temp.json && mv temp.json "$output_file"

    done

fi

if [ "$no_execute" = "true" ]; then
    echo "No execute mode enabled. Skipping execution."
    exit 0
fi

if [ -n "$prefix" ]; then
    echo "Using $output_file"
    usersjson=$output_file
fi

# Load users.json and iterate through each user
jq -c '.[]' "$usersjson" | while read -r user; do
    # if not the specific user and $user matches specific user
    name=$(echo "$user" | jq -r '.name')
    mnemonic=$(echo "$user" | jq -r '.mnemonic')
    a=$(echo "$user" | jq -r '.a')
    bf=$(echo "$user" | jq -r '.bf')
    firstname=$(echo "$user" | jq -r '.firstname')
    middlename=$(echo "$user" | jq -r '.middlename')
    lastname=$(echo "$user" | jq -r '.lastname')
    birthdate=$(echo "$user" | jq -r '.birthdate')
    citizenship=$(echo "$user" | jq -r '.citizenship')
    residency=$(echo "$user" | jq -r '.residency')
    gender=$(echo "$user" | jq -r '.gender')
    email=$(echo "$user" | jq -r '.email')
    phone=$(echo "$user" | jq -r '.phone')
    acceptcredentialtypes=$(echo "$user" | jq -r '."accept-credential-types" // ""')
    acceptpassword=$(echo "$user" | jq -r '."accept-password" // ""')
    requiresendertypes=$(echo "$user" | jq -r '."require-sender-credential-types" // ""')

    # Call setup_user.sh in parallel and store the process ID
    if [[ -n "$specific_user" && "$name" != "$specific_user" ]]; then
        echo "Looking for $specific_user, skipping user: $name"
    else
    echo "Processing user: $name"
        $qadenatestscripts/setup_user.sh "$name" "$mnemonic" "$pioneer" "$serviceprovider" "$firstname" "$middlename" "$lastname" "$birthdate" "$citizenship" "$residency" "$gender" "$email" "$phone" "$a" "$bf" "$identityprovider" "$acceptcredentialtypes" "$acceptpassword" "$requiresendertypes"> logs/"$name".log 2>&1 &

        pid_list+=($!)  # Store process ID

        # map the pid to the user name
        pids[$!]=$name
    fi
done

# Wait for all processes to finish and capture errors
errors=0

# Wait for all processes to finish
echo "Waiting for user setups to finish..."
for pid in $pid_list; do
    wait $pid
    ret=$?

    if [[ $ret -ne 0 ]]; then
        errors=$((errors + 1))  # Capture failure count
        echo "❌ Error: ${pids[$pid]}"  # Correct array syntax for Zsh

        # Rename the log file correctly
        mv logs/"${pids[$pid]}".log logs/"${pids[$pid]}_error.log"
    else 
        echo "✅ ${pids[$pid]} finished successfully."
    fi
done

# Check if any errors occurred
if [[ $errors -gt 0 ]]; then
    echo "❌ Some user setups failed ($errors errors).  Stop."
    exit 1  # Exit with error status
else
    echo "✅ All users have been processed successfully."

    if [[ -n "$specific_user" ]]; then
      echo "Skipping user recovery setup because a specific user was specified."
      exit 0
    fi

    echo "Now processing user recovery setup..."

    pid_list=()

    jq -c '.[]' "$usersjson" | while read -r user; do
        # if not the specific user and $user matches specific user
        name=$(echo "$user" | jq -r '.name')
        mnemonic=$(echo "$user" | jq -r '.mnemonic')
        required=$(echo "$user" | jq -r '.recovery.required // ""')
        partners=$(echo "$user" | jq -r '.recovery.partners // [] | join(" ")')

        # Call setup_user.sh in parallel and store the process ID
        if [[ -z "$required"  ]]; then
            echo "No recovery settings for user: $name"
        else
            echo "Setting up user recovery: $name"
            $qadenatestscripts/setup_user_recovery.sh "$name" "$mnemonic" "$required" "$partners" >> logs/"$name".log 2>&1 &

            pid_list+=($!)  # Store process ID
        fi
    done

    errors=0
    echo "Waiting for user recovery setup to finish..."
    for pid in $pid_list; do
        wait $pid || errors=$((errors + 1))  # Capture failure count
    done

    # Check if any errors occurred
    if [[ $errors -gt 0 ]]; then
        echo "❌ Some user recovery setups failed ($errors errors)."
        exit 1  # Exit with error status
    else
        echo "✅ All user recoveries have been processed successfully."
    fi

    exit 0  # Success
fi