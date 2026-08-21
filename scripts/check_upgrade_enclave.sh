#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

# check $QADENAHOME/enclave_config for all JSON files
if [[ ! -d "$QADENAHOME/enclave_config" ]] ; then
    echo "$QADENAHOME/enclave_config does not exist, no upgrade."
    exit 0
fi

# check if there are no files
#
# THIS GUARD USED TO DISABLE THE WHOLE SCRIPT.  It was written as
#
#     [[ ! -f "$QADENAHOME/enclave_config/enclave_params_*.json" ]] && exit 0
#
# but zsh does NOT perform filename generation inside [[ ]] -- quoted or not -- so -f tested a
# literal filename containing an asterisk, which never exists.  The negation was therefore always
# true and the script exited 0 on every single run, reporting "no upgrade" without ever comparing a
# version.  Every enclave upgrade was silently skipped, and run.sh saw a clean exit and started the
# new enclave with no migration.
#
# The (N) qualifier expands the glob properly and yields an empty array rather than an error when
# nothing matches.
params_files=("$QADENAHOME"/enclave_config/enclave_params_*.json(N))
if (( ${#params_files} == 0 )) ; then
    echo "$QADENAHOME/enclave_config does not contain any enclave config files, no upgrade."
    exit 0
fi

# Initialize variables for tracking latest version
latest_version=""
latest_type=""

# Function to compare version strings (MAJOR.MINOR.BUILD format)
compare_versions() {
    IFS='.' read -r v1_major v1_minor v1_build <<< "$1"
    IFS='.' read -r v2_major v2_minor v2_build <<< "$2"
    
    # Compare major version
    if (( v1_major > v2_major )); then
        return 0
    elif (( v1_major < v2_major )); then
        return 1
    fi
    
    # Compare minor version
    if (( v1_minor > v2_minor )); then
        return 0
    elif (( v1_minor < v2_minor )); then
        return 1
    fi
    
    # Compare build version
    if (( v1_build > v2_build )); then
        return 0
    elif (( v1_build < v2_build )); then
        return 1
    fi
    
    # Versions are equal
    return 1
}

# Find all enclave param JSON files and check their corresponding executables
for json_file in "$QADENAHOME/enclave_config"/enclave_params_*.json ; do
    if [[ -f "$json_file" ]] ; then
        # Extract the xxx part from enclave_params_xxx.json
        basename=$(basename "$json_file")
        enclave_type=${basename#enclave_params_}
        enclave_type=${enclave_type%.json}
        
        # Check for corresponding executable
        executable="$QADENAHOME/bin/qadenad_enclave.$enclave_type"
        if [[ -x "$executable" ]] ; then
            echo "Found enclave type: $enclave_type"
            echo "Checking version of $executable..."
            version=$("$executable" -version)
            echo "$enclave_type version: $version"
            
            # Update latest version if this is higher or if it's the first version found
            if [[ -z "$latest_version" ]] || compare_versions "$version" "$latest_version"; then
                latest_version="$version"
                latest_type="$enclave_type"
            fi
            echo "---"
        else
            echo "Warning: No executable found for enclave type $enclave_type"
            echo "Expected at: $executable"
            echo "---"
        fi
    fi
done

if [[ -n "$latest_version" ]] ; then
    echo "Latest version found: $latest_version (type: $latest_type)"
    
    # Check main enclave executable version
    main_executable="$QADENAHOME/bin/qadenad_enclave"
    if [[ -x "$main_executable" ]] ; then
        echo "Checking version of main enclave executable..."
        main_version=$("$main_executable" -version)
        # ALWAYS NAME BOTH SIDES.  These messages used to report a version without the measurement it
        # belongs to, so "No upgrade needed. Main version (1.1.6) is not higher than..." read as
        # success while actually meaning "you rebuilt at a version that is already taken, and nothing
        # happened".  The measurement is what the chain trusts and the version only schedules the
        # handover, so a decision stated in versions alone cannot be checked by the person reading it.
        # NOT `-unique-id`: on an SGX build that reports the embedded debug label rather than
        # MRENCLAVE, so the message would name a measurement the chain has never heard of.
        source "$qadenascripts/enclave_lib.sh" 2>/dev/null
        main_unique=$(enclave_measurement "$main_executable" 2>/dev/null)
        echo "Main enclave: ${main_unique:-unknown} (version $main_version)"
        
        # Compare versions and upgrade if main version is higher
        if compare_versions "$main_version" "$latest_version"; then
            echo "UPGRADE: ${latest_type} (version ${latest_version})  ->  ${main_unique:-unknown} (version ${main_version})"
            echo "Initiating upgrade from enclave type: $latest_type to ${main_unique:-unknown}"
            # absolute, not ./upgrade_enclave.sh -- run.sh invokes this script by full path from
            # whatever directory it was started in, so the relative form only resolved when the
            # caller happened to be sitting in scripts/
            "$qadenascripts/upgrade_enclave.sh" --from-enclave-unique-id "$latest_type"
            RES=$?
            if [ $RES -ne 0 ] ; then
                echo "Error: Upgrade failed"
                exit $RES
            else
                echo "Upgrade successful"
                exit 0
            fi
        else
            echo "No upgrade needed: this binary is ${main_unique:-unknown} (version $main_version); the newest"
            echo "  enclave already holding sealed params is $latest_type (version $latest_version)."
            if [[ "$main_version" == "$latest_version" ]]; then
                echo "  The versions are EQUAL, and an upgrade requires a STRICT increase.  If you meant to"
                echo "  deploy a new measurement, bump cmd/qadenad_enclave/version.txt -- rebuilding at a"
                echo "  version that is already taken does nothing and looks exactly like this."
            fi
            exit 0
        fi
    else
        echo "Error: Main enclave executable not found at $main_executable"
        exit 1
    fi
else
    echo "No valid versions found"
    exit 1
fi

