#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

# SGX RUNS ONLY UNDER LINUX (in practice Ubuntu, which is what the ego toolchain targets), so this
# probe is Linux-only by construction: /proc/cpuinfo does not exist on macOS and the grep simply
# fails there, leaving REAL_ENCLAVE=0.  That is correct, not a fallback.
#
# This detects the CPU and NOTHING ELSE.  It does not know how the enclave binary was built --
# buildscripts/build_enclave.sh gates the ego build on --build-sgx and never reads this
# variable.  Runtime scripts must therefore branch on use_real_enclave <binary> (below), never on
# REAL_ENCLAVE alone.
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
    # if SUDO_USER
    if [[ -n "$SUDO_USER" ]]; then
        export QADENAHOME="$(getent passwd "$SUDO_USER" | cut -d: -f6)/qadena"
    else
        export QADENAHOME="$(cd ~ && pwd)/qadena"
    fi
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

# is_sgx_binary <path> -- true only for an ego-SIGNED SGX executable.
#
# `ego uniqueid` reads the enclave measurement out of the binary's Open Enclave section, so it
# succeeds on a signed binary and fails on one produced by a plain `go build`.  That is precisely the
# question being asked, and it needs no new tooling: run.sh already calls `ego uniqueid` on this very
# path to build the --enclave-unique-id flag.
is_sgx_binary() {
  local bin="$1"
  [[ -n "$bin" && -x "$bin" ]] || return 1
  command -v ego > /dev/null 2>&1 || return 1
  ego uniqueid "$bin" > /dev/null 2>&1
}

# use_real_enclave <path> -- the condition every runtime script should branch on.
#
# BOTH halves are required, and that is the whole point of this helper.
#
# REAL_ENCLAVE says only that the CPU reports SGX support (setup_env.sh greps /proc/cpuinfo).  It
# says NOTHING about how <path> was built -- buildscripts/build_enclave.sh gates the ego-go/ego sign
# build on --build-sgx and never consults REAL_ENCLAVE at all.  So on SGX hardware carrying
# a debug-built binary, branching on REAL_ENCLAVE alone sends a plain Go executable down the
# `ego run` path: the launch fails, `ego uniqueid` yields nothing, and run.sh interpolates an empty
# --enclave-unique-id.  Nothing in that failure names either cause.
#
# Ordered so the cheap CPU test short-circuits first: on a non-SGX host `ego` is never invoked, which
# matters because it usually is not installed there.
use_real_enclave() {
  [[ $REAL_ENCLAVE -eq 1 ]] || return 1
  is_sgx_binary "$1"
}

# warn_if_sgx_binary_missing <name> <path> -- say so, once, when the hardware and the binary disagree.
#
# Falling back to the debug path silently would be its own trap: an operator who asked for a real
# enclave would get a simulated one and no indication of it.
warn_if_sgx_binary_missing() {
  local name="$1" bin="$2"
  if [[ $REAL_ENCLAVE -eq 1 ]] && ! is_sgx_binary "$bin"; then
      echo "$name:  WARNING: SGX hardware detected, but $bin is not an ego-signed enclave." >&2
      echo "$name:           Running in DEBUG (simulated) mode.  To build a real enclave:" >&2
      echo "$name:           buildscripts/build.sh --build-sgx" >&2
  fi
}

# needs_root_if_real_enclave <name> [binary]
#
# Root is required because `ego run` needs the SGX device -- so it must be decided by the SAME
# predicate that decides whether ego is used at all.  Gating on REAL_ENCLAVE alone demanded sudo for
# a debug run on SGX hardware, which never needed it.
#
# The binary argument is optional so existing callers keep working; without it the check falls back
# to the chain enclave, which is what every runtime script is ultimately gating on.
needs_root_if_real_enclave() {
  name="$1"
  bin="${2:-$qadenabin/qadenad_enclave}"
  if use_real_enclave "$bin"; then
      if [[ $(id -u) -ne 0 ]]; then
          echo "$name:  Error: Qadena must be run as root (real SGX enclave).  Try running with 'sudo'."
          exit 1
      fi
  fi
}

# wait_for_tx <broadcast-json> [label] -- check the broadcast BEFORE waiting for the transaction.
#
# THIS EXISTS BECAUSE THE OBVIOUS FORM HANGS FOREVER.  Every call site used to be
#
#     qadenad_alias ... query wait-tx $(echo "$RESP" | jq -r '.txhash') --timeout 30s
#
# and when the transaction was not broadcast at all -- a failed `--gas auto` simulation, most often
# -- $RESP is not JSON, `.txhash` is EMPTY, and that becomes `query wait-tx --timeout 30s` with no
# hash argument, which blocks indefinitely.  --timeout does not bound it.  A disbursement failure
# sat on that line for over seven minutes and stalled an entire regression run, and the error
# explaining it had already been printed and discarded.
#
# A hash is also returned for transactions REJECTED at CheckTx, which are never included in a block
# and so can never be found by waiting.  The code has to be read before the wait, not after it.
wait_for_tx() {
    local resp="$1" label="${2:-transaction}"

    local hash code
    hash=$(echo "$resp" | jq -r '.txhash // empty' 2>/dev/null)
    code=$(echo "$resp" | jq -r '.code // empty' 2>/dev/null)

    if [[ -z "$hash" ]]; then
        echo "wait_for_tx: $label was never broadcast -- no txhash in the response."
        echo "wait_for_tx: this is usually a failed gas simulation.  Response was:"
        echo "$resp" | head -5
        return 1
    fi

    if [[ -n "$code" && "$code" != "0" ]]; then
        echo "wait_for_tx: $label was REJECTED at CheckTx with code $code"
        echo "wait_for_tx: $(echo "$resp" | jq -r '.raw_log // empty' 2>/dev/null)"
        echo "wait_for_tx: it will never be included in a block, so it is not waited for."
        return 1
    fi

    qadenad_alias --node $QADENA_NODE query wait-tx "$hash" --timeout 30s
}

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

banner() {
  local msg="$*"
  local content=" $msg "
  local border
  border="$(printf '%*s' $(( ${#content} + 2 )) '' | tr ' ' '-')"
  echo "$border"
  echo "|$content|"
  echo "$border"
}

run_cmd() {
  local cmd="$*"
  local wrap_width=80
  local wrapped
  local maxlen=0
  local line
  local border
  local i=0

  wrapped="$(echo "$cmd" | fold -s -w "$wrap_width")"

  while IFS= read -r line; do
    if (( ${#line} > maxlen )); then
      maxlen=${#line}
    fi
  done <<< "$wrapped"

  border="$(printf '%*s' $(( maxlen + 6 )) '' | tr ' ' '*')"
  echo "$border"

  while IFS= read -r line; do
    i=$(( i + 1 ))
    if (( i == 1 )); then
      printf '* > %-*s *\n' "$maxlen" "$line"
    else
      printf '*   %-*s *\n' "$maxlen" "$line"
    fi
  done <<< "$wrapped"

  echo "$border"
  echo "Results:"
  eval "$cmd"
}

run_cmd_capture() {
  local cmd="$*"
  local wrap_width=80
  local wrapped
  local maxlen=0
  local line
  local border
  local i=0

  wrapped="$(echo "$cmd" | fold -s -w "$wrap_width")"

  while IFS= read -r line; do
    if (( ${#line} > maxlen )); then
      maxlen=${#line}
    fi
  done <<< "$wrapped"

  border="$(printf '%*s' $(( maxlen + 6 )) '' | tr ' ' '*')"
  echo "$border" >&2

  while IFS= read -r line; do
    i=$(( i + 1 ))
    if (( i == 1 )); then
      printf '* > %-*s *\n' "$maxlen" "$line" >&2
    else
      printf '*   %-*s *\n' "$maxlen" "$line" >&2
    fi
  done <<< "$wrapped"

  echo "$border" >&2
  echo "Results:" >&2
  eval "$cmd"
}
