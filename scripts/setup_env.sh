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

# extract minimum-gas-prices from config.yml
# check if config.yml exists
query_min_gas_price() {

  # if qadenad_alias is not executable, then return fallback
  if ! command -v qadenad_alias > /dev/null 2>&1; then
    # get from config.yml
    minimum_gas_prices=$(dasel -f $QADENAHOME/config/config.yml 'validators.first().app.minimum-gas-prices')
    echo "$minimum_gas_prices"
    return 0
  fi

  local fallback="$1"
  local denom="${2:-aqdn}"

  if ! command -v jq > /dev/null 2>&1; then
    echo "${fallback}"
    return 0
  fi

  if ! command -v python3 > /dev/null 2>&1; then
    echo "${fallback}"
    return 0
  fi

  local params_json
  params_json=$(qadenad_alias query feemarket params --output json 2>/dev/null)
  if [[ "$params_json" == "" ]] ; then
    echo "${fallback}"
    return 0
  fi

  local min_gas_price
  local base_fee
  min_gas_price=$(echo "$params_json" | jq -r '.params.min_gas_price // empty')
  base_fee=$(echo "$params_json" | jq -r '.params.base_fee // empty')

  if [[ "$min_gas_price" == "" || "$min_gas_price" == "null" || "$min_gas_price" == "0" || "$min_gas_price" == "0.0" ]] ; then
    echo "${fallback}"
    return 0
  fi

  local buffered_int
  buffered_int=$(MIN_GAS_PRICE="$min_gas_price" BASE_FEE="$base_fee" python3 - <<'PY'
import os
from decimal import Decimal, getcontext

getcontext().prec = 80
def to_dec(s: str) -> Decimal:
    if not s or s == 'null':
        return Decimal(0)
    return Decimal(s)

mgp = to_dec(os.environ.get('MIN_GAS_PRICE', ''))
bf = to_dec(os.environ.get('BASE_FEE', ''))
chosen = max(mgp, bf)
buffered = chosen * Decimal('1.1')
print(int(buffered))
PY
  )

  if [[ "$buffered_int" == "" ]] ; then
    echo "${fallback}"
    return 0
  fi

  echo "${buffered_int}${denom}"
}

minimum_gas_prices=$(query_min_gas_price)
export minimum_gas_prices
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

