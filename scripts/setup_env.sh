#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

if grep sgx /proc/cpuinfo > /dev/null 2> /dev/null ; then
    echo "SGX detected"
    export REAL_ENCLAVE=1
else
    echo "SGX not detected"
    export REAL_ENCLAVE=0
fi

if [[ "$DOCKER_BUILD" = "1" ]]; then
    echo "Docker build"
else
    echo "Host"
fi

# check SCRIPT_DIR/../cmd and SCRIPT_DIR/../x  -- if they exist, then we are in a build environment
if [[ -d "$SCRIPT_DIR/../cmd" && -d "$SCRIPT_DIR/../x" ]]; then
    export QADENAHOME="$(cd ~ && pwd)/qadena"
    export qadenabuild="$(cd "$SCRIPT_DIR/.." && pwd)"
    export qadenabuildscripts="$qadenabuild/buildscripts"
    export qadenascripts="$qadenabuild/scripts"
    export qadenatestscripts="$qadenabuild/testscripts"
    echo "Qadena build: $qadenabuild"
    echo "Qadena build scripts: $qadenabuildscripts"
else
    # resolve $SCRIPT_DIR/.. to absolute path
    export QADENAHOME="$(cd "$SCRIPT_DIR/.." && pwd)"
    export qadenascripts="$QADENAHOME/scripts"
    export qadenatestscripts="$QADENAHOME/testscripts"
fi

export qadenabin="$QADENAHOME/bin"
alias qadenad_alias="$qadenabin/qadenad --home $QADENAHOME"
export qadenad_binary="$qadenabin/qadenad"

echo "Qadena home: $QADENAHOME"
echo "Qadena bin: $qadenabin"
echo "Qadena scripts: $qadenascripts"

# COMMON FUNCTIONS
# Function to increment the number in a string
increment_id() {
  local current_val
  current_val=$(<"$1") # Read file content

  # Extract numeric part and increment
  local prefix="${current_val%%[0-9]*}" # Get non-numeric prefix
  local number="${current_val##*[!0-9]}" # Get numeric part
  local new_number=$((10#$number + 1))  # Increment with base 10

  # Format to maintain leading zeros if necessary
  local new_value="${prefix}$(printf "%03d" "$new_number")"

  # Write back to the file
  echo -n "$new_value" > "$1"

  echo "$new_value"
}

# Function to increment the version
increment_version() {
  local current_val
  current_val=$(<"$1") # Read file content

  # Extract Major, Minor, and Build numbers
  local MAJOR=$(echo "$current_val" | cut -d. -f1)
  local MINOR=$(echo "$current_val" | cut -d. -f2)
  local BUILD=$(echo "$current_val" | cut -d. -f3)

  # Increment the Build number
  local NEW_BUILD=$((BUILD + 1))

  # Construct the new version
  local NEW_VERSION="$MAJOR.$MINOR.$NEW_BUILD"

  # Write back to the file
  echo -n "$NEW_VERSION" > "$1"

  echo "$NEW_VERSION"
}

