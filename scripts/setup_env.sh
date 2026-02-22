#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

if grep sgx /proc/cpuinfo > /dev/null 2> /dev/null ; then
    # echo to stderr
    echo "SGX detected" >&2
    export REAL_ENCLAVE=1
else
    # echo to stderr
    echo "SGX not detected" >&2
    export REAL_ENCLAVE=0
fi

if [[ "$DOCKER_BUILD" = "1" ]]; then
    # echo to stderr
    echo "Docker build" >&2
else
    # echo to stderr
    echo "Host" >&2
fi

# check SCRIPT_DIR/../cmd and SCRIPT_DIR/../x  -- if they exist, then we are in a build environment
if [[ -d "$SCRIPT_DIR/../cmd" && -d "$SCRIPT_DIR/../x" ]]; then
    export QADENAHOME="$(cd ~ && pwd)/qadena"
    export qadenabuild="$(cd "$SCRIPT_DIR/.." && pwd)"
    export qadenabuildscripts="$qadenabuild/buildscripts"
    export qadenascripts="$qadenabuild/scripts"
    export qadenatestscripts="$qadenabuild/testscripts"
    export qadenatestdata="$qadenabuild/test_data"
    export qadenaproviderscripts="$qadenabuild/provider_scripts"
    export veritasscripts="$qadenabuild/veritas_scripts"

    echo "Qadena build: $qadenabuild" >&2
    echo "Qadena build scripts: $qadenabuildscripts" >&2
else
    # resolve $SCRIPT_DIR/.. to absolute path
    export QADENAHOME="$(cd "$SCRIPT_DIR/.." && pwd)"
    export qadenascripts="$QADENAHOME/scripts"
#    export qadenatestscripts="$QADENAHOME/testscripts"
    export qadenaproviderscripts="$QADENAHOME/provider_scripts"
    export veritasscripts="$QADENAHOME/veritas_scripts"
fi

export qadenabin="$QADENAHOME/bin"
alias qadenad_alias="$qadenabin/qadenad --home $QADENAHOME"
export qadenad_binary="$qadenabin/qadenad"

export LD_LIBRARY_PATH="$qadenabin:$LD_LIBRARY_PATH"

# echo to stderr
echo "Qadena home: $QADENAHOME" >&2
echo "Qadena bin: $qadenabin" >&2
echo "Qadena scripts: $qadenascripts" >&2

is_zero() {
  val="$1"

  # normalize empty/null
  if [ -z "$val" ] || [ "$val" = "null" ]; then
    return 0
  fi

  eps="0.000000000000001"
  if echo "v=($val); if (v<0) v=-v; v < $eps" | bc -l | grep -q 1; then
    return 0
  fi
  return 1
}

is_greater_than() {
  a="$1"
  b="$2"

  if [ -z "$a" ] || [ "$a" = "null" ]; then
    a=0
  fi
  if [ -z "$b" ] || [ "$b" = "null" ]; then
    b=0
  fi

  if echo "$a > $b" | bc -l | grep -q 1; then
    return 0
  fi
  return 1
}

# extract minimum-gas-prices from config.yml
# check if config.yml exists
set_min_gas_price() {

  fallback=false

  # if qadenad_alias is not executable, then return fallback
  if ! command -v qadenad_alias > /dev/null 2>&1; then
    #echo "qadenad_alias not found, will try to get minimum gas prices from config.yml"
    fallback=true
  fi

  if ! command -v jq > /dev/null 2>&1; then
    #echo "jq not found, will try to get minimum gas prices from config.yml"
    fallback=true
  fi

  local params_json
  params_json=$(qadenad_alias query feemarket params --output json 2>/dev/null)
  if [[ "$params_json" == "" ]] ; then
    #echo "feemarket params not found, will try to get minimum gas prices from config.yml"
    fallback=true
  fi

  if [ "$fallback" = true ]; then
    #echo "Using fallback minimum gas prices from config.yml"
    if [[ ! -f $QADENAHOME/config/config.yml ]]; then
        minimum_gas_prices="500000000aqdn"
        export minimum_gas_prices
        return
    fi
    minimum_gas_prices="$(dasel -f $QADENAHOME/config/config.yml 'validators.first().app.minimum-gas-prices')aqdn"

    export minimum_gas_prices
    #echo "Found minimum gas prices: $minimum_gas_prices"
    return
  fi

  local min_gas_price
  local base_fee
  min_gas_price=$(echo "$params_json" | jq -r '.params.min_gas_price // 0')
  base_fee=$(echo "$params_json" | jq -r '.params.base_fee // 0')

  #echo "min_gas_price: $min_gas_price"
  #echo "base_fee: $base_fee"

  if is_zero "$min_gas_price" && is_zero "$base_fee"; then
    #echo "feemarket params are effectively zero, will try to get minimum gas prices from config.yml"
    fallback=true
  fi

  # take the max of min_gas_price and base_fee using bc
  if is_greater_than "$min_gas_price" "$base_fee"; then
    minimum_gas_prices="$min_gas_price"
  else
    minimum_gas_prices="$base_fee"
  fi

  # add 10% buffer
  minimum_gas_prices=$(echo "$minimum_gas_prices * 1.1" | bc)

  # add 1
  minimum_gas_prices=$(echo "$minimum_gas_prices + 1" | bc)

  #echo "Using minimum gas prices: $minimum_gas_prices"
  minimum_gas_prices="${minimum_gas_prices}aqdn"

  export minimum_gas_prices
  return
}

set_min_gas_price
gas_adjustment=1.5
gas_auto=auto

# export
export gas_adjustment

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

# function to detect if all of the qadena processes are running

is_qadena_running() {
  if pgrep -x qadenad >/dev/null ||
     pgrep -x qadenad_enclave >/dev/null ||
     pgrep -af 'ego-host.*qadenad_enclave' ||
     pgrep -af 'ego-host.*signer_enclave' ||
     pgrep -x signer_enclave >/dev/null; then
    echo "Qadena is running"
    return 0
  else
    echo "Qadena is not running"
    return 1
  fi
}