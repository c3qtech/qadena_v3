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

# TWO SEPARATE QUESTIONS, and conflating them is what produced the sudo-everywhere habit:
#
#   Q1  Is there SGX here?              -> do we run under `ego` at all, or simulate?
#   Q2  Can THIS USER open the devices? -> do we need root?
#
# Q1 is answered by REAL_ENCLAVE + is_sgx_binary (see use_real_enclave above) and by sgx_present
# below.  Q2 is answered by sgx_usable_by_me, and is the ONLY question the root decision may
# consult.  Keeping them apart matters: an earlier single tri-state predicate let "no devices found"
# satisfy the ROOT check, so a machine with no SGX but an ego-signed binary got neither a root check
# nor a clear statement that it was about to simulate -- two different conditions sharing one answer.

# sgx_enclave_dev / sgx_provision_dev -- the in-kernel driver's two device nodes, or empty.
#
# /dev/sgx/{enclave,provision} are the compatibility symlinks the driver package creates; -e and
# -r/-w follow them, so either spelling works.
#
# /dev/isgx is deliberately NOT accepted.  That is the out-of-tree pre-5.11 driver's single node,
# which has no separate provisioning device.  ubuntu/setup_qadena_build.sh provisions only the two
# modern devices, and ego targets the in-kernel driver, so treating an isgx box as SGX-ready would
# promise attestation it structurally cannot deliver.
sgx_enclave_dev() {
  local d
  for d in /dev/sgx_enclave /dev/sgx/enclave; do [[ -e $d ]] && { print "$d"; return 0 } ; done
  return 1
}
sgx_provision_dev() {
  local d
  for d in /dev/sgx_provision /dev/sgx/provision; do [[ -e $d ]] && { print "$d"; return 0 } ; done
  return 1
}

# sgx_present -- Q1.  BOTH devices must exist.
#
# Both, not either: /dev/sgx_enclave runs the enclave, /dev/sgx_provision holds the provisioning key
# that ATTESTATION needs.  getRemoteReport/verifyRemoteReport gate sync-enclave, secret shares and
# the private-state transfer, so a box with only the first will run an enclave and then fail at JOIN
# time with an error naming a measurement rather than a missing device.
sgx_present() {
  sgx_enclave_dev > /dev/null && sgx_provision_dev > /dev/null
}

# sgx_usable_by_me -- Q2.  Both devices exist AND this user can open them.
#
# The test is -r/-w, i.e. access(2), which honours GROUP MEMBERSHIP -- exactly what `id -u` cannot
# see.  ubuntu/setup_qadena_build.sh adds the login user to the groups owning the devices (`sgx` for
# the enclave node and the DIFFERENT group `sgx_prv` for provisioning), so on a provisioned machine
# this is true and root is not needed at all.  Measured on .120:
#
#     crw-rw---- 1 root sgx     /dev/sgx_enclave
#     crw-rw---- 1 root sgx_prv /dev/sgx_provision
#     uid=1000(alvillarica) groups=...,108(sgx),...,1001(sgx_prv)
#
# access(2) is preferred over comparing `id -nG` with `stat -c %G` because it also covers what plain
# membership would miss: a device relaxed to 666, an ACL, or the caller already being root.  Where
# the two disagree, this one is right -- it answers "will the open succeed" rather than "does a rule
# imply it should".
sgx_usable_by_me() {
  local encl prov
  encl=$(sgx_enclave_dev)   || return 1
  prov=$(sgx_provision_dev) || return 1
  [[ -r $encl && -w $encl && -r $prov && -w $prov ]]
}

# needs_root_if_real_enclave <name> [binary]
#
# ROOT IS NOT A QADENA REQUIREMENT.  `ego run` needs to OPEN the SGX devices; whether that takes root
# depends on their group and this user's membership of it, which setup_qadena_build.sh already
# arranges.  This used to demand uid 0 whenever the enclave was real -- wrong on every machine that
# script had provisioned, and expensive: running as root makes every file the node creates
# root-owned, so `rm -rf ~/qadena` as the login user then fails on every entry, the next install
# refuses because it cannot overwrite what is there, and the enclave's own unix socket is left in
# sticky /tmp where only root can unlink it.  That last one is not theoretical -- see the stale
# socket handling in cmd/qadenad_enclave/enclave.go, which exists because of it.
#
# So: refuse only when the devices are genuinely out of reach, and say what to DO about it.  Joining
# the group is the fix; sudo is the workaround, and the message says what the workaround costs.
#
# The binary argument is optional so existing callers keep working; without it the check falls back
# to the chain enclave, which is what every runtime script is ultimately gating on.
needs_root_if_real_enclave() {
  name="$1"
  bin="${2:-$qadenabin/qadenad_enclave}"

  use_real_enclave "$bin" || return 0    # Q1 false: simulating, no device to open
  [[ $(id -u) -eq 0 ]]    && return 0    # already root, which opens them by definition
  sgx_usable_by_me        && return 0    # Q2 true: this is the normal, provisioned case

  if ! sgx_present; then
      echo "$name:  Error: this build is a real SGX enclave, but the SGX devices are not both present." >&2
      echo "$name:         enclave:    ${$(sgx_enclave_dev):-MISSING}" >&2
      echo "$name:         provision:  ${$(sgx_provision_dev):-MISSING}" >&2
      echo "$name:         Provisioning is required for ATTESTATION -- without it the enclave runs but" >&2
      echo "$name:         cannot quote, and the failure surfaces later as a rejected join." >&2
      echo "$name:         Install the in-kernel SGX driver (ubuntu/setup_qadena_build.sh)." >&2
      exit 1
  fi

  # Present but not ours: name the REAL groups rather than assuming sgx/sgx_prv.
  local encl prov groups
  encl=$(sgx_enclave_dev); prov=$(sgx_provision_dev)
  groups=$(stat -c %G "$encl" 2>/dev/null; stat -c %G "$prov" 2>/dev/null)
  groups=$(echo "$groups" | sort -u | tr '\n' ',' | sed 's/,$//')

  echo "$name:  Error: the SGX devices exist but $(id -un) cannot open them." >&2
  echo "$name:         Fix (preferred): join the groups that own them, then log in again --" >&2
  echo "$name:             sudo usermod -aG $groups $(id -un)" >&2
  echo "$name:         Workaround: re-run with sudo.  Note that this makes every file the node" >&2
  echo "$name:         creates root-owned, including /tmp/qadena_*.sock in sticky /tmp, which only" >&2
  echo "$name:         root can then remove -- so the next unprivileged start will fail to bind." >&2
  exit 1
}

# as_enclave_owner <command...> -- run one command as whoever owns the enclave.
#
# The counterpart to needs_root_if_real_enclave, for callers that must NOT themselves become root.
# The test suites run as the login user and need to keep doing so: they write logs and use the
# keyring under $QADENAHOME, and running the whole suite as root would leave root-owned files
# behind for the next unprivileged run to trip over.
#
# But on SGX the enclave PROCESS and its unix socket belong to root, because `ego run` needs
# /dev/sgx_enclave.  So a suite that signals the enclave or talks to it gets EPERM:
#
#     kill 3152561 failed: operation not permitted
#     dial unix /tmp/qadena_50051.sock: connect: permission denied
#
# and reports "cannot SIGSTOP the enclave" or "cannot read the enclave's store hashes" -- both of
# which read as a BROKEN ENCLAVE rather than a permission boundary.  That cost a real diagnosis:
# enclave-rollback and enclave-crash both failed within two seconds on a healthy SGX node, which
# looks exactly like the regression those suites exist to catch.
#
# On a debug node the enclave runs unprivileged and this is a no-op, which is why the predicate is
# use_real_enclave rather than "am I on SGX hardware" -- a debug enclave on SGX hardware needs no
# sudo, and asking for it would prompt for a password in a suite that must not block.
# THE PREDICATE IS OWNERSHIP, not "is this a real enclave", and the difference matters in both
# directions.  A real SGX enclave does NOT inherently need root: setup_qadena_build.sh adds the
# login user to the sgx and sgx_prv groups, and a node started unprivileged then owns its own
# socket, where elevating would be pointless.  Equally, a node someone started with sudo needs it
# whether or not SGX is involved.  Asking who actually owns the process answers both without
# assuming a deployment style.
#
# sudo -n, not plain sudo: a suite that stops on an invisible password prompt looks like a hang, and
# these run unattended from run_regression_continually.sh.  Failing immediately with "a password is
# required" is a diagnosable message; blocking forever is not.
#
# The bracket classes in the patterns are not decoration -- see the pkill warning in
# nth_node_bringup.sh.  A plain `pgrep -f qadenad_enclave` matches the shell running this very
# function when the suite was invoked over ssh.
as_enclave_owner() {
  # A DEBUG ENCLAVE NEVER NEEDS ELEVATION, and must never attempt it.  It runs as whoever started
  # the node -- us -- and a debug machine may have no sudo configured at all, so reaching for it
  # there would break runs that work today.  This is the FIRST check for that reason: everything
  # below is about real enclaves only.
  #
  # Gating on the BINARY rather than on the hardware is deliberate.  A debug enclave running on SGX
  # hardware still needs no privilege, which is the same distinction needs_root_if_real_enclave
  # draws and for the same reason.
  use_real_enclave "$qadenabin/qadenad_enclave" || { "$@"; return $? }

  # Already root: there is nothing to elevate to.
  [[ $(id -u) -eq 0 ]] && { "$@"; return $? }

  # A real enclave WE started needs no elevation either.  That is not hypothetical --
  # setup_qadena_build.sh puts the login user in the sgx and sgx_prv groups, so an SGX node can be
  # started unprivileged and then owns its own socket (see backlog item 30).
  local pid owner
  pid=$(pgrep -f "ego-host.*qadenad_enclav[e]" 2>/dev/null | head -1)
  if [[ -n "$pid" ]]; then
      owner=$(ps -o user= -p "$pid" 2>/dev/null | tr -d ' ')
      [[ -n "$owner" && "$owner" == "$(id -un)" ]] && { "$@"; return $? }
  fi

  # A real enclave owned by someone else -- or one we cannot identify, where guessing "no" would
  # reproduce the EPERM this function exists to fix.
  sudo -n "$@"
}

# confirm_tx <hash> [seconds] -- did this transaction land, and did it succeed?
#
# `query wait-tx` alone is NOT a reliable answer.  It SUBSCRIBES to a websocket event, so a
# transaction that was already included before the subscription was established never produces one
# and the command times out -- reporting failure for a transaction that succeeded.  A freshly started
# node makes that likely, because the first transactions are committed while the client is still
# connecting.
#
# That is not hypothetical: it failed setup_prerequisites.sh with "could not vote on proposal 2"
# while the proposal had in fact PASSED, and took the idempotency suite down with it on the re-run.
#
# So the event is treated as a fast path and the CHAIN as the authority: if waiting does not answer,
# ask what actually happened.
confirm_tx() {
    local hash="$1" secs="${2:-30}"

    [ -n "$hash" ] && [ "$hash" != "null" ] || { echo "confirm_tx: no transaction hash"; return 1; }

    qadenad_alias query wait-tx "$hash" --timeout "${secs}s" > /dev/null 2>&1

    # Poll regardless of how the wait turned out -- it may have missed the event, and it may also
    # have returned before the transaction was indexed.
    local code i
    for i in $(seq 1 "$secs"); do
        code=$(qadenad_alias query tx "$hash" --output json 2>/dev/null | jq -r '.code // empty' 2>/dev/null)
        [ -n "$code" ] && break
        sleep 1
    done

    if [ -z "$code" ]; then
        echo "confirm_tx: $hash never appeared on chain within ${secs}s"
        return 1
    fi
    if [ "$code" != "0" ]; then
        echo "confirm_tx: $hash failed with code $code: $(qadenad_alias query tx "$hash" --output json 2>/dev/null | jq -r '.raw_log // empty' 2>/dev/null)"
        return 1
    fi
    return 0
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
# EVERY FAILURE PATH PRINTS THE WORD "UNCONFIRMED", and that is a contract callers depend on.
# cadena_cli.sh `full` returns 0 no matter what fails inside it, so its exit code cannot be used to
# tell whether the transactions actually landed -- a suite could only assert on state afterwards and
# INFER success.  That inference is what let a stalled disbursement report PASS: the transaction had
# long since landed while the flow sat blocked on a wait that could never finish, so the state check
# found its record and saw nothing wrong.  A single grep for UNCONFIRMED gives suites the fact they
# could not otherwise get.
wait_for_tx() {
    local resp="$1" label="${2:-transaction}"

    local hash code
    hash=$(echo "$resp" | jq -r '.txhash // empty' 2>/dev/null)
    code=$(echo "$resp" | jq -r '.code // empty' 2>/dev/null)

    if [[ -z "$hash" ]]; then
        echo "wait_for_tx: UNCONFIRMED -- $label was never broadcast, no txhash in the response."
        echo "wait_for_tx: this is usually a failed gas simulation, whose error goes to STDERR"
        echo "wait_for_tx: while only stdout is captured -- so run the caller with 2>&1 to see it."
        echo "wait_for_tx: response was:"
        echo "$resp" | head -5
        return 1
    fi

    if [[ -n "$code" && "$code" != "0" ]]; then
        echo "wait_for_tx: UNCONFIRMED -- $label was REJECTED at CheckTx with code $code"
        echo "wait_for_tx: $(echo "$resp" | jq -r '.raw_log // empty' 2>/dev/null)"
        echo "wait_for_tx: it will never be included in a block, so it is not waited for."
        return 1
    fi

    # The WAIT ITSELF CAN FAIL, and that was previously swallowed too: a timeout, or a transaction
    # that failed in DeliverTx, left the flow continuing as though the write had happened.
    if ! qadenad_alias --node $QADENA_NODE query wait-tx "$hash" --timeout 30s; then
        echo "wait_for_tx: UNCONFIRMED -- $label ($hash) was not confirmed within 30s."
        echo "wait_for_tx: it was accepted at CheckTx, so it may still land later; nothing that"
        echo "wait_for_tx: depends on it has happened yet."
        return 1
    fi
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
    #
    # THE DENOM IS ONLY APPENDED IF IT IS NOT ALREADY THERE.  config.yml carries a full coin string
    # ("500000000aqdn"), not a bare number, so appending unconditionally produced
    #
    #     expected only native token aqdn for fee, but got 54683000000000aqdnaqdn
    #
    # and every transaction using $minimum_gas_prices was rejected at broadcast.  It hid well: this
    # branch only runs when the feemarket query fails, which is exactly what happens when
    # regression.sh sources this file at the start of a --from-genesis run -- before the chain it is
    # about to build exists.  So the fallback, and therefore the bug, is guaranteed on precisely the
    # runs that build a new chain, and absent on every run against a live one.
    minimum_gas_prices="$(dasel -f $QADENAHOME/config/config.yml 'validators.first().app.minimum-gas-prices')"
    case "$minimum_gas_prices" in
        *aqdn) ;;
        *) minimum_gas_prices="${minimum_gas_prices}aqdn" ;;
    esac

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
